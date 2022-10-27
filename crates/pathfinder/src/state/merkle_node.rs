//! Contains constructs for describing the nodes in a Binary Merkle Patricia Tree
//! used by Starknet.
//!
//! For more information about how these Starknet trees are structured, see
//! [`MerkleTree`](super::merkle_tree::MerkleTree).

use std::{cell::RefCell, ops::Index, rc::Rc};

use bitvec::{
    order::Msb0,
    prelude::{BitArray, BitVec},
    slice::BitSlice,
};
use stark_hash::{stark_hash, StarkHash};

/// A node in a Binary Merkle-Patricia Tree graph.
#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    /// A node that has not been fetched from storage yet.
    ///
    /// As such, all we know is its hash.
    Unresolved(StarkHash),
    /// A branch node with exactly two children.
    Binary(BinaryNode),
    /// Describes a path connecting two other nodes.
    Edge(EdgeNode),
    /// A leaf node that contains a value.
    Leaf(StarkHash),
}

/// Describes the [Node::Binary] variant.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryNode {
    /// The hash of this node. Is [None] if the node
    /// has not yet been committed.
    pub hash: Option<StarkHash>,
    /// The height of this node in the tree.
    pub height: usize,
    /// [Left](Direction::Left) child.
    pub left: Rc<RefCell<Node>>,
    /// [Right](Direction::Right) child.
    pub right: Rc<RefCell<Node>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EdgeNode {
    /// The hash of this node. Is [None] if the node
    /// has not yet been committed.
    pub hash: Option<StarkHash>,
    /// The starting height of this node in the tree.
    pub height: usize,
    /// The path this edge takes.
    pub path: Path,
    /// The child of this node.
    pub child: Rc<RefCell<Node>>,
}

/// Describes the direction a child of a [BinaryNode] may have.
///
/// Binary nodes have two children, one left and one right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Left,
    Right,
}

impl Direction {
    /// Inverts the [Direction].
    ///
    /// [Left] becomes [Right], and [Right] becomes [Left].
    ///
    /// [Left]: Direction::Left
    /// [Right]: Direction::Right
    pub fn invert(self) -> Direction {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

impl From<bool> for Direction {
    fn from(tf: bool) -> Self {
        match tf {
            true => Direction::Right,
            false => Direction::Left,
        }
    }
}

impl From<Direction> for bool {
    fn from(direction: Direction) -> Self {
        match direction {
            Direction::Left => false,
            Direction::Right => true,
        }
    }
}

impl BinaryNode {
    /// Maps the key's bit at the binary node's height to a [Direction].
    ///
    /// This can be used to check which direction the key descibes in the context
    /// of this binary node i.e. which direction the child along the key's path would
    /// take.
    pub fn direction(&self, key: &BitSlice<Msb0, u8>) -> Direction {
        key[self.height].into()
    }

    /// Returns the [Left] or [Right] child.
    ///
    /// [Left]: Direction::Left
    /// [Right]: Direction::Right
    pub fn get_child(&self, direction: Direction) -> Rc<RefCell<Node>> {
        match direction {
            Direction::Left => self.left.clone(),
            Direction::Right => self.right.clone(),
        }
    }

    /// If possible, calculates and sets its own hash value.
    ///
    /// Does nothing if the hash is already [Some].
    ///
    /// If either childs hash is [None], then the hash cannot
    /// be calculated and it will remain [None].
    pub(crate) fn calculate_hash(&mut self) {
        if self.hash.is_some() {
            return;
        }

        let left = match self.left.borrow().hash() {
            Some(hash) => hash,
            None => unreachable!("subtrees have to be commited first"),
        };

        let right = match self.right.borrow().hash() {
            Some(hash) => hash,
            None => unreachable!("subtrees have to be commited first"),
        };

        self.hash = Some(stark_hash(left, right));
    }
}

impl Node {
    /// Convenience function which sets the inner node's hash to [None], if
    /// applicable.
    ///
    /// Used to indicate that this node has been mutated.
    pub fn mark_dirty(&mut self) {
        match self {
            Node::Binary(inner) => inner.hash = None,
            Node::Edge(inner) => inner.hash = None,
            _ => {}
        }
    }

    /// Returns true if the node represents an empty node -- this is defined as a node
    /// with the [StarkHash::ZERO].
    ///
    /// This can occur for the root node in an empty graph.
    pub fn is_empty(&self) -> bool {
        match self {
            Node::Unresolved(hash) => hash == &StarkHash::ZERO,
            _ => false,
        }
    }

    pub fn is_binary(&self) -> bool {
        matches!(self, Node::Binary(..))
    }

    pub fn as_binary(&self) -> Option<&BinaryNode> {
        match self {
            Node::Binary(binary) => Some(binary),
            _ => None,
        }
    }

    pub fn as_edge(&self) -> Option<&EdgeNode> {
        match self {
            Node::Edge(edge) => Some(edge),
            _ => None,
        }
    }

    pub fn hash(&self) -> Option<StarkHash> {
        match self {
            Node::Unresolved(hash) => Some(*hash),
            Node::Binary(binary) => binary.hash,
            Node::Edge(edge) => edge.hash,
            Node::Leaf(value) => Some(*value),
        }
    }
}

impl EdgeNode {
    /// Returns true if the edge node's path matches the same path given by the key.
    pub fn path_matches(&self, key: &BitSlice<Msb0, u8>) -> bool {
        self.path.as_bitslice() == key[self.height..self.height + self.path.len()]
    }

    /// Returns the common bit prefix between the edge node's path and the given key.
    ///
    /// This is calculated with the edge's height taken into account.
    pub fn common_path(&self, key: &BitSlice<Msb0, u8>) -> &BitSlice<Msb0, u8> {
        let key_path = key.iter().skip(self.height);
        let common_length = key_path
            .zip(self.path.iter())
            .take_while(|(a, b)| a == b)
            .count();

        &self.path.as_bitslice()[..common_length]
    }

    /// If possible, calculates and sets its own hash value.
    ///
    /// Does nothing if the hash is already [Some].
    ///
    /// If the child's hash is [None], then the hash cannot
    /// be calculated and it will remain [None].
    pub(crate) fn calculate_hash(&mut self) {
        if self.hash.is_some() {
            return;
        }

        let child = match self.child.borrow().hash() {
            Some(hash) => hash,
            None => unreachable!("subtree has to be commited before"),
        };

        let path = StarkHash::from_bits(self.path.as_bitslice()).unwrap();
        let mut length = [0; 32];
        // Safe as len() is guaranteed to be <= 251
        length[31] = self.path.len() as u8;

        let length = StarkHash::from_be_bytes(length).unwrap();
        let hash = stark_hash(child, path) + length;
        self.hash = Some(hash);
    }
}

/// On-stack `BitArray` wrapper that resembles a `BitVector` in its api.
/// Contains up to 256 bits accessable mostly via a `BitSlice`.
#[derive(Copy, Clone, Debug, Default, Eq)]
pub struct Path {
    pub storage: BitArray<Msb0, [u8; 32]>,
    len: usize,
}

impl Path {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extend_from_bitslice(&mut self, other: &BitSlice<Msb0, u8>) {
        let start = self.len;
        let stop = start + other.len();
        self.storage[start..stop].copy_from_bitslice(other);
        self.len += other.len();
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_bitslice(&self) -> &BitSlice<Msb0, u8> {
        &self.storage[..self.len]
    }

    pub fn iter(&self) -> bitvec::slice::Iter<'_, Msb0, u8> {
        self.as_bitslice().iter()
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Panics when capacity exceeded
    pub fn push(&mut self, value: bool) {
        self.storage.set(self.len, value);
        self.len += 1;
    }
}

impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        self.storage == other.storage
    }
}

impl From<&BitSlice<Msb0, u8>> for Path {
    fn from(s: &BitSlice<Msb0, u8>) -> Self {
        let mut path = Self::default();
        path.extend_from_bitslice(s);
        path
    }
}

impl From<BitVec<Msb0, u8>> for Path {
    fn from(v: BitVec<Msb0, u8>) -> Self {
        let mut path = Self::default();
        path.extend_from_bitslice(&v[..]);
        path
    }
}

impl From<Direction> for Path {
    fn from(value: Direction) -> Self {
        let mut path = Self::default();
        path.push(value.into());
        path
    }
}

impl<Idx> Index<Idx> for Path
where
    BitSlice<Msb0, u8>: Index<Idx>,
{
    type Output = <BitSlice<Msb0, u8> as Index<Idx>>::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.as_bitslice()[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod direction {
        use super::*;
        use Direction::*;

        #[test]
        fn invert() {
            assert_eq!(Left.invert(), Right);
            assert_eq!(Right.invert(), Left);
        }

        #[test]
        fn bool_round_trip() {
            assert_eq!(Direction::from(bool::from(Left)), Left);
            assert_eq!(Direction::from(bool::from(Right)), Right);
        }

        #[test]
        fn right_is_true() {
            assert!(bool::from(Right));
        }

        #[test]
        fn left_is_false() {
            assert!(!bool::from(Left));
        }
    }

    mod binary {
        use super::*;
        use crate::starkhash;
        use bitvec::bitvec;

        #[test]
        fn direction() {
            let uut = BinaryNode {
                hash: None,
                height: 1,
                left: Rc::new(RefCell::new(Node::Leaf(starkhash!("0abc")))),
                right: Rc::new(RefCell::new(Node::Leaf(starkhash!("0def")))),
            };

            let mut zero_key = bitvec![Msb0, u8; 1; 251];
            zero_key.set(1, false);

            let mut one_key = bitvec![Msb0, u8; 0; 251];
            one_key.set(1, true);

            let zero_direction = uut.direction(&zero_key);
            let one_direction = uut.direction(&one_key);

            assert_eq!(zero_direction, Direction::from(false));
            assert_eq!(one_direction, Direction::from(true));
        }

        #[test]
        fn get_child() {
            let left = Rc::new(RefCell::new(Node::Leaf(starkhash!("0abc"))));
            let right = Rc::new(RefCell::new(Node::Leaf(starkhash!("0def"))));

            let uut = BinaryNode {
                hash: None,
                height: 1,
                left: left.clone(),
                right: right.clone(),
            };

            use Direction::*;
            assert_eq!(uut.get_child(Left), left);
            assert_eq!(uut.get_child(Right), right);
        }

        #[test]
        fn hash() {
            // Test data taken from starkware cairo-lang repo:
            // https://github.com/starkware-libs/cairo-lang/blob/fc97bdd8322a7df043c87c371634b26c15ed6cee/src/starkware/starkware_utils/commitment_tree/patricia_tree/nodes_test.py#L14
            //
            // Note that the hash function must be exchanged for `async_stark_hash_func`, otherwise it just uses some other test hash function.
            let expected = StarkHash::from_hex_str(
                "0615bb8d47888d2987ad0c63fc06e9e771930986a4dd8adc55617febfcf3639e",
            )
            .unwrap();
            let left = starkhash!("1234");
            let right = starkhash!("abcd");

            let left = Rc::new(RefCell::new(Node::Unresolved(left)));
            let right = Rc::new(RefCell::new(Node::Unresolved(right)));

            let mut uut = BinaryNode {
                hash: None,
                height: 0,
                left,
                right,
            };

            uut.calculate_hash();

            assert_eq!(uut.hash, Some(expected));
        }
    }

    mod edge {
        use super::*;
        use crate::starkhash;
        use bitvec::bitvec;

        #[test]
        fn hash() {
            // Test data taken from starkware cairo-lang repo:
            // https://github.com/starkware-libs/cairo-lang/blob/fc97bdd8322a7df043c87c371634b26c15ed6cee/src/starkware/starkware_utils/commitment_tree/patricia_tree/nodes_test.py#L38
            //
            // Note that the hash function must be exchanged for `async_stark_hash_func`, otherwise it just uses some other test hash function.
            let expected = StarkHash::from_hex_str(
                "1d937094c09b5f8e26a662d21911871e3cbc6858d55cc49af9848ea6fed4e9",
            )
            .unwrap();
            let child = starkhash!("1234ABCD");
            let child = Rc::new(RefCell::new(Node::Unresolved(child)));
            // Path = 42 in binary.
            let path = bitvec![Msb0, u8; 1, 0, 1, 0, 1, 0].into();

            let mut uut = EdgeNode {
                hash: None,
                height: 0,
                path,
                child,
            };

            uut.calculate_hash();

            assert_eq!(uut.hash, Some(expected));
        }

        mod path_matches {
            use super::*;
            use crate::starkhash;

            #[test]
            fn full() {
                let key = starkhash!("0123456789abcdef");
                let child = Rc::new(RefCell::new(Node::Leaf(starkhash!("0abc"))));

                let uut = EdgeNode {
                    hash: None,
                    height: 0,
                    path: key.view_bits().into(),
                    child,
                };

                assert!(uut.path_matches(key.view_bits()));
            }

            #[test]
            fn prefix() {
                let key = starkhash!("0123456789abcdef");
                let child = Rc::new(RefCell::new(Node::Leaf(starkhash!("0abc"))));

                let path = key.view_bits()[..45].into();

                let uut = EdgeNode {
                    hash: None,
                    height: 0,
                    path,
                    child,
                };

                assert!(uut.path_matches(key.view_bits()));
            }

            #[test]
            fn suffix() {
                let key = starkhash!("0123456789abcdef");
                let child = Rc::new(RefCell::new(Node::Leaf(starkhash!("0abc"))));

                let path = key.view_bits()[50..].into();

                let uut = EdgeNode {
                    hash: None,
                    height: 50,
                    path,
                    child,
                };

                assert!(uut.path_matches(key.view_bits()));
            }

            #[test]
            fn middle_slice() {
                let key = starkhash!("0123456789abcdef");
                let child = Rc::new(RefCell::new(Node::Leaf(starkhash!("0abc"))));

                let path = key.view_bits()[230..235].into();

                let uut = EdgeNode {
                    hash: None,
                    height: 230,
                    path,
                    child,
                };

                assert!(uut.path_matches(key.view_bits()));
            }
        }
    }

    mod path {
        use bitvec::{
            bitvec,
            prelude::{BitArray, Msb0},
        };

        use crate::state::merkle_node::{Direction, Path};

        #[test]
        fn new_and_default() {
            let n = Path::new();
            let d = Path::default();
            assert_eq!(n, d);
            assert_eq!(n.len(), 0);
            assert!(n.is_empty());
            assert_eq!(n.iter().count(), 0);
            assert_eq!(n.storage, BitArray::<Msb0, [u8; 32]>::zeroed());
            assert!(n.as_bitslice().is_empty());
        }

        #[test]
        fn from_bitslice_or_equivalent() {
            [
                bitvec![Msb0, u8;],
                bitvec![Msb0, u8; 0, 1, 1, 0, 1],
                bitvec![Msb0, u8; 0, 128],
                bitvec![Msb0, u8; 1, 256],
            ]
            .into_iter()
            .for_each(|expected| {
                let mut extended = Path::new();
                extended.extend_from_bitslice(&expected);
                let from_slice = Path::from(&expected[..]);
                let from_vec = Path::from(expected.clone());

                assert_eq!(extended.len(), expected.len());
                assert_eq!(extended.as_bitslice(), expected);
                assert_eq!(extended, from_slice);
                assert_eq!(extended, from_vec);

                expected.iter().enumerate().for_each(|(i, expected_value)| {
                    assert_eq!(expected_value, extended[i]);
                });
            });
        }

        #[test]
        fn from_direction() {
            let left = Path::from(Direction::Left);
            assert_eq!(left.len(), 1);
            assert!(!left[0]);

            let right = Path::from(Direction::Right);
            assert_eq!(right.len(), 1);
            assert!(right[0]);
        }

        #[test]
        fn index() {
            assert!(Path::default()[..].is_empty());

            let expected = bitvec![Msb0, u8; 0, 1, 1, 0, 1, 1];
            let p = Path::from(expected);

            assert!(p[1]);
            assert_eq!(p[2..5], bitvec![Msb0, u8; 1, 0, 1]);
        }
    }
}
