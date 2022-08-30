#![allow(dead_code, unused_variables)]

use std::collections::HashMap;

use anyhow::Context;
use pathfinder_lib::{
    core::{ContractAddress, GlobalRoot, StarknetBlockNumber, StorageAddress, StorageValue},
    storage::{StarknetBlocksTable, StarknetStateUpdatesTable},
};
use rusqlite::{Connection, Transaction};
use stark_hash::StarkHash;

fn main() -> anyhow::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let database_path = std::env::args()
        .nth(1)
        .context("Database path expected as arg")?;
    let storage = pathfinder_lib::storage::Storage::migrate(
        database_path.into(),
        pathfinder_lib::storage::JournalMode::WAL,
    )?;
    let mut conn = storage
        .connection()
        .context("Opening database connection")?;

    let latest = setup(&mut conn).context("Setup")?;

    for block in 0..latest.get() {
        let state_update = get_state_update(&mut conn, StarknetBlockNumber::new_or_panic(block))
            .context("Fetching state update")?;

        // apply update to RC tree
        let time = std::time::Instant::now();
        do_reference_count(&mut conn, &state_update)
            .with_context(|| format!("Applying state update for block {}", block))?;
        let time = time.elapsed();
        tracing::info!(?time, ?block, "State updated");

        // apply update to HashMap
    }

    Ok(())
}

/// Re-creates the required tree tables and returns the latest [StarknetBlockNumber].
///
/// Tables created (existing tables will be dropped):
/// - tree_rc_global
/// - tree_rc_contracts
/// - tree_hashmap_global
/// - tree_hashmap_contracts
fn setup(conn: &mut Connection) -> anyhow::Result<StarknetBlockNumber> {
    let tx = conn.transaction().context("Create database transaction")?;
    let latest = StarknetBlocksTable::get_latest_number(&tx)
        .context("Reading latest block number")?
        .context("Latest block number missing")?;

    // Re-creates the tree table with the given name.
    let create_table = |tx: &Transaction<'_>, table_name| -> anyhow::Result<()> {
        tx.execute(&format!("DROP TABLE IF EXISTS {}", table_name), [])
            .context("Dropping existing table")?;

        tx.execute(
            &format!(
                r"CREATE TABLE {} (
            hash BLOB PRIMARY KEY,
            data BLOB,
            ref_count INTEGER
        )",
                table_name
            ),
            [],
        )
        .context("Creating table")?;
        Ok(())
    };

    create_table(&tx, "tree_rc_global").context("Creating tree_rc_global table")?;
    create_table(&tx, "tree_rc_contracts").context("Creating tree_rc_contracts table")?;
    create_table(&tx, "tree_hashmap_global").context("Creating tree_hashmap_global table")?;
    create_table(&tx, "tree_hashmap_contracts").context("Creating tree_hashmap_contracts table")?;

    tx.commit().context("Committing transaction")?;

    Ok(latest)
}

fn get_state_update(
    conn: &mut Connection,
    block_number: StarknetBlockNumber,
) -> anyhow::Result<StateUpdate> {
    let tx = conn.transaction().context("Create database transaction")?;

    let block_hash = StarknetBlocksTable::get_hash(&tx, block_number.into())
        .context("Reading block hash from database")?
        .context("Block hash missing")?;

    let update = StarknetStateUpdatesTable::get(&tx, block_hash)
        .context("Reading state update")?
        .context("State update missing")?
        .into();

    Ok(update)
}

struct StateUpdate {
    pub updates: HashMap<ContractAddress, ContractUpdate>,
    pub old_root: GlobalRoot,
    pub new_root: GlobalRoot,
}

// impl StateUpdate {
//     fn merge_deploys(&mut self, block:)
// }

#[derive(Default, PartialEq, Debug)]
struct ContractUpdate {
    pub updates: HashMap<StorageAddress, StorageValue>,
}

type RpcStateDiff = pathfinder_lib::rpc::types::reply::StateUpdate;

impl From<RpcStateDiff> for StateUpdate {
    fn from(v: RpcStateDiff) -> Self {
        let mut updates: HashMap<ContractAddress, ContractUpdate> = HashMap::new();

        for deploy in v.state_diff.deployed_contracts {
            let original = updates.insert(deploy.address, ContractUpdate::default());
            assert_eq!(original, None);
        }

        for diff in v.state_diff.storage_diffs {
            let original = updates
                .entry(diff.address)
                .or_default()
                .updates
                .insert(diff.key, diff.value);
            assert_ne!(
                original,
                Some(diff.value),
                "Redundant storage update found when setting {}.{} = {}",
                diff.address,
                diff.key,
                diff.value
            );
        }

        StateUpdate {
            updates,
            old_root: v.old_root,
            new_root: v.new_root,
        }
    }
}

fn do_reference_count(conn: &mut Connection, state_update: &StateUpdate) -> anyhow::Result<()> {
    use pathfinder_lib::core::{ContractRoot, ContractStateHash};
    use pathfinder_lib::state::calculate_contract_state_hash;
    use pathfinder_lib::state::merkle_tree::MerkleTree;
    use pathfinder_lib::storage::merkle_tree::RcNodeStorage;
    use pathfinder_lib::storage::ContractsStateTable;
    use pathfinder_lib::storage::ContractsTable;

    fn update_contract(
        tx: &Transaction<'_>,
        address: ContractAddress,
        update: &ContractUpdate,
        global: &MerkleTree<RcNodeStorage>,
    ) -> anyhow::Result<ContractRoot> {
        let state_hash = global
            .get(address.view_bits())
            .context("Fetching state hash")?;
        let state_hash = ContractStateHash(state_hash);

        let root = ContractsStateTable::get_root(&tx, state_hash)
            .context("Fetching contract root")?
            .unwrap_or(ContractRoot(StarkHash::ZERO));

        let mut tree = MerkleTree::load("tree_rc_contracts", &tx, root.0)?;

        for (key, value) in &update.updates {
            tree.set(key.view_bits(), value.0)
                .with_context(|| format!("Setting {} = {}", key, value))?;
        }

        let new_root = tree.commit().context("Committing contract tree")?;

        Ok(ContractRoot(new_root))
    }

    let tx = conn.transaction().context("Create transaction")?;
    let mut global = MerkleTree::load("tree_rc_global", &tx, state_update.old_root.0)?;

    for (address, update) in &state_update.updates {
        let new_root = update_contract(&tx, *address, update, &global)
            .with_context(|| format!("Updating contract {}", address))?;

        let class_hash = ContractsTable::get_hash(&tx, *address)
            .context("Read class hash from contracts table")?
            .context("Class hash is missing from contracts table")?;

        let new_hash = calculate_contract_state_hash(class_hash, new_root);

        global
            .set(address.view_bits(), new_hash.0)
            .with_context(|| format!("Setting state hash for {}", address))?;
    }

    let new_root = global.commit().context("Committing global tree")?;
    let new_root = GlobalRoot(new_root);
    anyhow::ensure!(new_root == state_update.new_root, "State root mismatch!");

    tx.commit().context("Committing transaction")?;

    Ok(())
}

fn do_hashmap(conn: &mut Connection, update: &StateUpdate) -> anyhow::Result<()> {
    todo!();
}
