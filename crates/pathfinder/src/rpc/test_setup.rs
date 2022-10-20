///! Utilities for easier construction of RPC tests.
use crate::core::Chain;
use crate::rpc::test_client::client;
use crate::rpc::{RpcApi, RpcServer};
use crate::sequencer::reply::{PendingBlock, StateUpdate};
use crate::sequencer::Client;
use crate::state::PendingData;
use crate::state::SyncState;
use crate::storage::{fixtures::RawPendingData, Storage};
use ::serde::de::DeserializeOwned;
use ::serde::Serialize;
use jsonrpsee::http_server::HttpServerHandle;
use jsonrpsee::rpc_params;
use rusqlite::Transaction;
use std::fmt::Debug;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

pub struct Test<'a> {
    method: &'a str,
    line: u32,
    storage: Storage,
}

impl<'a> Test<'a> {
    /// Create test setup with empty in-memory storage.
    pub fn new(method: &'a str, line: u32) -> Self {
        Self {
            method,
            line,
            storage: Storage::in_memory().unwrap(),
        }
    }

    /// Initialize test setup storage using function `f`.
    /// `f` **must produce a sequence of the items put into the storage
    /// in the very same order as they were inserted**.
    pub fn with_storage<StorageInitFn, StorageInitIntoIterator, StorageInitItem>(
        self,
        f: StorageInitFn,
    ) -> TestWithStorage<'a, StorageInitIntoIterator::IntoIter>
    where
        StorageInitIntoIterator: IntoIterator<Item = StorageInitItem>,
        StorageInitFn: FnOnce(&Transaction<'_>) -> StorageInitIntoIterator,
    {
        let mut connection = self.storage.connection().unwrap();
        let tx = connection.transaction().unwrap();
        let storage_init = f(&tx);
        tx.commit().unwrap();
        TestWithStorage {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: storage_init.into_iter(),
        }
    }
}

pub struct TestWithStorage<'a, StorageInitIter> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
}

impl<'a, StorageInitIter> TestWithStorage<'a, StorageInitIter> {
    /// The calls to `pending` will yield pending data from
    /// 1. the iterable collection created by the mapping function `f`
    /// 2. and when the resulting iterator is exhausted __empty__ pending data is returned
    pub fn map_pending_then_empty_then_disabled<PendingInitFn, PendingInitIntoIterator>(
        self,
        f: PendingInitFn,
    ) -> TestWithPending<'a, StorageInitIter, PendingInitIntoIterator::IntoIter>
    where
        StorageInitIter: Clone,
        PendingInitIntoIterator: IntoIterator<Item = RawPendingData>,
        PendingInitFn: FnOnce(&Transaction<'_>, StorageInitIter) -> PendingInitIntoIterator,
    {
        let mut connection = self.storage.connection().unwrap();
        let tx = connection.transaction().unwrap();
        let pending_init = f(&tx, self.storage_init.clone());
        tx.commit().unwrap();
        TestWithPending {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            pending_init: pending_init.into_iter(),
        }
    }
}

pub struct TestWithPending<'a, StorageInitIter, PendingInitIter> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
    pending_init: PendingInitIter,
}

impl<'a, StorageInitIter, PendingInitIter> TestWithPending<'a, StorageInitIter, PendingInitIter> {
    /// Initialize test setup with a sequence of test params.
    /// Each item in the sequence corresponds to a separate test case.
    #[allow(dead_code)]
    pub fn with_params<ParamsIntoIterator, ParamsItem>(
        self,
        params: ParamsIntoIterator,
    ) -> TestWithParams<'a, StorageInitIter, PendingInitIter, ParamsIntoIterator::IntoIter>
    where
        ParamsItem: Serialize,
        ParamsIntoIterator: IntoIterator<Item = ParamsItem>,
    {
        TestWithParams {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            pending_init: self.pending_init,
            params: params.into_iter(),
        }
    }

    /// Initialize test setup with a sequence of test params
    /// which are of type `serde_json::Value`.
    /// Each item in the sequence corresponds to a separate test case.
    ///
    /// Useful for handling test cases where consecutive param sets
    /// contain vastly different variants.
    #[allow(dead_code)]
    pub fn with_params_json0<ParamsIntoIterator>(
        self,
        params: ParamsIntoIterator,
    ) -> TestWithParams<'a, StorageInitIter, PendingInitIter, ParamsIntoIterator::IntoIter>
    where
        ParamsIntoIterator: IntoIterator<Item = &'a serde_json::Value>,
    {
        TestWithParams {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            pending_init: self.pending_init,
            params: params.into_iter(),
        }
    }

    /// Initialize test setup with a single json array.
    /// Each item in the json array corresponds to a separate test case.
    /// **Any other json type will be automatically wrapped in a json
    /// array and treated as a single test case.**
    ///
    /// Useful for handling test cases where consecutive param sets
    /// contain vastly different variants.
    pub fn with_params_json(
        self,
        params: serde_json::Value,
    ) -> TestWithParams<
        'a,
        StorageInitIter,
        PendingInitIter,
        impl Clone + Iterator<Item = serde_json::Value>,
    > {
        let params = match params {
            serde_json::Value::Array(v) => v,
            _ => vec![params],
        };

        TestWithParams {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            pending_init: self.pending_init,
            params: params.into_iter(),
        }
    }
}

pub struct TestWithParams<'a, StorageInitIter, PendingInitIter, ParamsIter> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
    pending_init: PendingInitIter,
    params: ParamsIter,
}

impl<'a, StorageInitIter, PendingInitIter, ParamsIter>
    TestWithParams<'a, StorageInitIter, PendingInitIter, ParamsIter>
{
    /// Map actual `jsonrpsee::core::Error` replies from the RPC server to a more manageable type,
    /// so that expressing the actual expected outputs is easier.
    /// The mapping function also takes the line and test case numbers.
    pub fn map_err<MapErrFn, MappedError>(
        self,
        f: MapErrFn,
    ) -> TestWithMapErr<'a, StorageInitIter, PendingInitIter, ParamsIter, MapErrFn>
    where
        MapErrFn: FnOnce(jsonrpsee::core::Error, &str) -> MappedError,
    {
        TestWithMapErr {
            method: self.method,
            line: self.line,
            storage: self.storage,
            storage_init: self.storage_init,
            pending_init: self.pending_init,
            params: self.params,
            map_err_fn: f,
        }
    }

    /// Map actual `jsonrpsee::core::Error` replies from the RPC server to [StarkWare error codes](crate::rpc::types::reply::ErrorCode),
    /// so that expressing the actual expected outputs is easier.
    /// Panics if the mapping fails, outputing the actual `jsonrpsee::core::Error`, line, and test case numbers.
    pub fn map_err_to_starkware_error_code(
        self,
    ) -> TestWithMapErr<
        'a,
        StorageInitIter,
        PendingInitIter,
        ParamsIter,
        impl Copy + FnOnce(jsonrpsee::core::Error, &str) -> crate::rpc::v01::types::reply::ErrorCode,
    > {
        self.map_err(|error, test_case_descr| match &error {
            jsonrpsee::core::Error::Call(jsonrpsee::types::error::CallError::Custom(custom)) => {
                match crate::rpc::v01::types::reply::ErrorCode::try_from(custom.code()) {
                    Ok(error_code) => error_code,
                    Err(_) => {
                        panic!("{test_case_descr}, mapping to starkware error code failed: {error}")
                    }
                }
            }
            _ => panic!("{test_case_descr}, expected custom call error, got: {error}"),
        })
    }
}

pub struct TestWithMapErr<'a, StorageInitIter, PendingInitIter, ParamsIter, MapErrFn> {
    method: &'a str,
    line: u32,
    storage: Storage,
    storage_init: StorageInitIter,
    pending_init: PendingInitIter,
    params: ParamsIter,
    map_err_fn: MapErrFn,
}

impl<'a, StorageInitIter, PendingInitIter, ParamsIter, MapErrFn>
    TestWithMapErr<'a, StorageInitIter, PendingInitIter, ParamsIter, MapErrFn>
{
    /// Initialize test setup with a sequence of expected test outputs.
    ///
    /// - Each item in the resulting sequence corresponds to a separate test case.
    /// - This function panics if the lenght of the `expected` sequence
    /// is different from the `params` sequence in [`GotStorage::with_params`].
    #[allow(dead_code)]
    pub fn with_expected<ExpectedIntoIterator, ExpectedIter, ExpectedOk, MappedError>(
        self,
        expected: ExpectedIntoIterator,
    ) -> TestWithExpected<'a, PendingInitIter, ParamsIter, ExpectedIntoIterator::IntoIter, MapErrFn>
    where
        ExpectedIntoIterator: IntoIterator<Item = Result<ExpectedOk, MappedError>>,
        <ExpectedIntoIterator as IntoIterator>::IntoIter: Clone,
        ExpectedOk: Clone,
        ParamsIter: Clone + Iterator,
    {
        let expected_iter = expected.into_iter();
        let expected_cnt = expected_iter.clone().count();
        let params_cnt = self.params.clone().count();
        std::assert_eq!(params_cnt, expected_cnt,
                        "numbers of test cases from vectors differ (params: {params_cnt}, expected outputs: {expected_cnt}), line {}", self.line);
        TestWithExpected {
            method: self.method,
            line: self.line,
            storage: self.storage,
            pending_init: self.pending_init,
            params: self.params,
            expected: expected_iter,
            map_err_fn: self.map_err_fn,
        }
    }

    /// Initialize test setup with a sequence of expected test outputs
    /// by mapping from the storage initialization sequence.
    /// Useful for test cases where expected outputs are the same or very
    /// similar types to what was inserted into storage upon its initialization.
    ///
    /// - Each item in the resulting sequence corresponds to a separate test case.
    /// - This function panics if the lenght of the `expected` sequence
    /// is different from the `params` sequence in [`GotStorage::with_params`].
    pub fn map_expected<
        StorageAndPendingInitToExpectedMapperFn,
        ExpectedIntoIterator,
        ExpectedOk,
        MappedError,
    >(
        self,
        f: StorageAndPendingInitToExpectedMapperFn,
    ) -> TestWithExpected<'a, PendingInitIter, ParamsIter, ExpectedIntoIterator::IntoIter, MapErrFn>
    where
        PendingInitIter: Clone,
        StorageAndPendingInitToExpectedMapperFn:
            FnOnce(StorageInitIter, PendingInitIter) -> ExpectedIntoIterator,
        ExpectedIntoIterator: IntoIterator<Item = Result<ExpectedOk, MappedError>>,
        <ExpectedIntoIterator as IntoIterator>::IntoIter: Clone,
        ExpectedOk: Clone,
        ParamsIter: Clone + Iterator,
    {
        let expected_iter = f(self.storage_init, self.pending_init.clone()).into_iter();
        let expected_cnt = expected_iter.clone().count();
        let params_cnt = self.params.clone().count();
        std::assert_eq!(params_cnt, expected_cnt,
                        "numbers of test cases from vectors differ (params: {params_cnt}, expected outputs: {expected_cnt}), line {}", self.line);
        TestWithExpected {
            method: self.method,
            line: self.line,
            storage: self.storage,
            pending_init: self.pending_init,
            params: self.params,
            expected: expected_iter,
            map_err_fn: self.map_err_fn,
        }
    }
}

pub struct TestWithExpected<'a, PendingInitIter, ParamsIter, ExpectedIter, MapErrFn> {
    method: &'a str,
    line: u32,
    storage: Storage,
    pending_init: PendingInitIter,
    params: ParamsIter,
    expected: ExpectedIter,
    map_err_fn: MapErrFn,
}

impl<'a, PendingInitIter, ParamsIter, ExpectedIter, MapErrFn>
    TestWithExpected<'a, PendingInitIter, ParamsIter, ExpectedIter, MapErrFn>
{
    pub fn then_expect_internal_err_when_pending_disabled<PendingParams>(
        self,
        params: PendingParams,
        error_msg: String,
    ) -> TestWithPendingDisabled<
        'a,
        PendingInitIter,
        ParamsIter,
        ExpectedIter,
        MapErrFn,
        PendingParams,
    > {
        TestWithPendingDisabled {
            method: self.method,
            line: self.line,
            storage: self.storage,
            pending_init: self.pending_init,
            params: self.params,
            expected: self.expected,
            map_err_fn: self.map_err_fn,
            pending_disabled: PendingDisabled { params, error_msg },
        }
    }
}

/// Holds data required for a disabled pending scenario
struct PendingDisabled<Params> {
    params: Params,
    error_msg: String,
}

pub struct TestWithPendingDisabled<
    'a,
    PendingInitIter,
    ParamsIter,
    ExpectedIter,
    MapErrFn,
    PendingParams,
> {
    method: &'a str,
    line: u32,
    storage: Storage,
    pending_init: PendingInitIter,
    params: ParamsIter,
    expected: ExpectedIter,
    map_err_fn: MapErrFn,
    pending_disabled: PendingDisabled<PendingParams>,
}

impl<
        'a,
        PendingInitIter,
        ParamsIter,
        ExpectedIter,
        ExpectedOk,
        MapErrFn,
        MappedError,
        PendingParams,
    >
    TestWithPendingDisabled<'a, PendingInitIter, ParamsIter, ExpectedIter, MapErrFn, PendingParams>
where
    PendingInitIter: Iterator<Item = RawPendingData>,
    ParamsIter: Iterator,
    ExpectedIter: Iterator<Item = Result<ExpectedOk, MappedError>>,
    ExpectedOk: Clone + DeserializeOwned + Debug + PartialEq,
    MapErrFn: FnOnce(jsonrpsee::core::Error, &str) -> MappedError + Copy,
    MappedError: Debug + PartialEq,
{
    /// Runs the test cases.
    pub async fn run(self)
    where
        <ParamsIter as Iterator>::Item: Debug + Serialize,
        PendingParams: Debug + Serialize,
    {
        let storage = self.storage;
        let sequencer = Client::new(Chain::Testnet).unwrap();
        let sync_state = Arc::new(SyncState::default());
        let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);

        let line = self.line;
        let params_iter = self.params;
        let expected_iter = self.expected;
        let mut pending_iter = self.pending_init;

        // Iterate through all the 'normal' scenarios
        for (test_case, (params, expected)) in params_iter.zip(expected_iter).enumerate() {
            let serialized_params = serialize_params(&params, line, test_case);
            let test_case_descr = test_case_descr(line, test_case, &serialized_params);
            let api = api_with_maybe_pending(&serialized_params, &mut pending_iter, &api).await;
            let (_handle, addr) = run_server(api, &test_case_descr).await;
            let client = client(addr);

            let params = rpc_params!(params);
            let actual = client.request::<ExpectedOk>(self.method, params).await;
            let actual = actual.map_err(|error| (self.map_err_fn)(error, &test_case_descr));
            std::assert_eq!(actual, expected, "{test_case_descr}",);
        }

        // Now the 'disabled pending' scenario
        let params = self.pending_disabled.params;
        let expected_error_msg = self.pending_disabled.error_msg;

        let test_case = "'disabled pending'";
        let serialized_params = serialize_params(&params, line, test_case);
        let test_case_descr = test_case_descr(line, test_case, &serialized_params);
        let (_handle, addr) = run_server(api, &test_case_descr).await;
        let client = client(addr);

        let params = rpc_params!(params);
        let actual = client.request::<ExpectedOk>(self.method, params).await;
        let error = actual.expect_err(&test_case_descr);

        use jsonrpsee::{core::error::Error, types::error::CallError};

        assert_matches::assert_matches!(error, Error::Call(CallError::Custom(error_object)) => {
            pretty_assertions::assert_eq!(error_object.message(), expected_error_msg, "{test_case_descr}");
            // Internal error
            // https://www.jsonrpc.org/specification#error_object
            pretty_assertions::assert_eq!(error_object.code(), -32603, "{test_case_descr}");
        });
    }
}

fn serialize_params<Params: Debug + Serialize, TestCase: ToString>(
    params: &Params,
    line: u32,
    test_case: TestCase,
) -> String {
    serde_json::to_string(&params).unwrap_or_else(|_| {
        panic!(
            "line {line}, test case {}, inputs should be serializable to JSON: {params:?}",
            test_case.to_string()
        )
    })
}

fn test_case_descr<TestCase: ToString>(
    line: u32,
    test_case: TestCase,
    serialized_params: &str,
) -> String {
    format!(
        "line {line}, test case {}, inputs {}",
        test_case.to_string(),
        serialized_params,
    )
}

async fn api_with_maybe_pending<PendingInitIter: Iterator<Item = RawPendingData>>(
    serialized_params: &str,
    pending_init_iter: &mut PendingInitIter,
    api: &RpcApi,
) -> RpcApi {
    // I know, this is fishy, but still works because `pending` is stictly defined
    if serialized_params.contains(r#"pending"#) {
        match pending_init_iter.next() {
            // Some valid pending data fixture is available, use it
            Some(pending_data) => {
                let block = pending_data.block.unwrap_or(PendingBlock::dummy_for_test());
                let state_update = pending_data
                    .state_update
                    .unwrap_or(StateUpdate::dummy_for_test());
                let pending_data = PendingData::default();
                pending_data
                    .set(Arc::new(block), Arc::new(state_update))
                    .await;
                api.clone().with_pending_data(pending_data)
            }
            // All valid pending data fixtures have been exhausted so __simulate empty pending data from now on__
            None => api.clone().with_pending_data(PendingData::default()),
        }
    } else {
        // Pending was not requested so just treat pending data as disabled
        api.clone()
    }
}

async fn run_server(api: RpcApi, failure_msg: &str) -> (HttpServerHandle, SocketAddr) {
    RpcServer::new(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        api,
    )
    .run()
    .await
    .expect(&failure_msg)
}
