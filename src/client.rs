/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod kinto_http;
mod signatures;
mod storage;

use log::{debug, info};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

use kinto_http::{get_changeset, get_latest_change_timestamp, KintoError, KintoObject};
pub use signatures::{SignatureError, Verification};
pub use storage::{
    dummy_storage::DummyStorage, file_storage::FileStorage, memory_storage::MemoryStorage, Storage,
    StorageError,
};

#[cfg(feature = "ring_verifier")]
use crate::client::signatures::ring_verifier::RingVerifier as DefaultVerifier;

#[cfg(not(feature = "ring_verifier"))]
use crate::client::signatures::default_verifier::DefaultVerifier;

pub const DEFAULT_SERVER_URL: &str = "https://firefox.settings.services.mozilla.com/v1";
pub const DEFAULT_BUCKET_NAME: &str = "main";

#[derive(Debug, PartialEq)]
pub enum ClientError {
    VerificationError { name: String },
    StorageError { name: String },
    Error { name: String },
}

impl From<KintoError> for ClientError {
    fn from(err: KintoError) -> Self {
        match err {
            KintoError::ServerError { name } => ClientError::Error { name },
            KintoError::ClientError { name } => ClientError::Error { name },
        }
    }
}

impl From<serde_json::error::Error> for ClientError {
    fn from(err: serde_json::error::Error) -> Self {
        ClientError::StorageError {
            name: format!("Could not de/serialize data: {}", err.to_string()),
        }
    }
}

impl From<StorageError> for ClientError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::ReadError { name } => ClientError::StorageError { name },
            StorageError::Error { name } => ClientError::StorageError { name },
        }
    }
}

impl From<SignatureError> for ClientError {
    fn from(err: SignatureError) -> Self {
        match err {
            SignatureError::CertificateError { name } => ClientError::VerificationError { name },
            SignatureError::VerificationError { name } => ClientError::VerificationError { name },
            SignatureError::InvalidSignature { name } => ClientError::VerificationError { name },
        }
    }
}

/// Representation of a collection on the server
#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
pub struct Collection {
    pub bid: String,
    pub cid: String,
    pub metadata: KintoObject,
    pub records: Vec<KintoObject>,
    pub timestamp: u64,
}

pub struct ClientBuilder {
    server_url: String,
    bucket_name: String,
    collection_name: String,
    verifier: Box<dyn Verification>,
    storage: Box<dyn Storage>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    /// Constructs a new `ClientBuilder`.
    ///
    /// This is the same as `Client::builder()`.
    pub fn new() -> ClientBuilder {
        ClientBuilder {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            bucket_name: DEFAULT_BUCKET_NAME.to_owned(),
            collection_name: "".to_owned(),
            verifier: Box::new(DefaultVerifier {}),
            storage: Box::new(DummyStorage {}),
        }
    }

    /// Add custom server url to Client
    pub fn server_url(mut self, server_url: &str) -> ClientBuilder {
        self.server_url = server_url.to_owned();
        self
    }

    /// Add custom bucket name to Client
    pub fn bucket_name(mut self, bucket_name: &str) -> ClientBuilder {
        self.bucket_name = bucket_name.to_owned();
        self
    }

    /// Add custom collection name to Client
    pub fn collection_name(mut self, collection_name: &str) -> ClientBuilder {
        self.collection_name = collection_name.to_owned();
        self
    }

    /// Add custom signature verifier to Client
    pub fn verifier(mut self, verifier: Box<dyn Verification>) -> ClientBuilder {
        self.verifier = verifier;
        self
    }

    /// Add custom storage implementation to Client
    pub fn storage(mut self, storage: Box<dyn Storage>) -> ClientBuilder {
        self.storage = storage;
        self
    }

    /// Build Client from ClientBuilder
    pub fn build(self) -> Client {
        Client {
            server_url: self.server_url,
            bucket_name: self.bucket_name,
            collection_name: self.collection_name,
            verifier: self.verifier,
            storage: self.storage,
        }
    }
}

/// Client to fetch Remote Settings data.
///
/// # Examples
/// Create a `Client` for the `cid` collection on the production server:
/// ```rust
/// # use remote_settings_client::Client;
///
/// # fn main() {
/// let client = Client::builder()
///   .collection_name("cid")
///   .build();
/// # }
/// ```
/// Or for a specific server or bucket:
/// ```rust
/// # use remote_settings_client::Client;
///
/// # fn main() {
/// let client = Client::builder()
///   .server_url("https://settings.stage.mozaws.net/v1")
///   .bucket_name("main-preview")
///   .collection_name("cid")
///   .build();
/// # }
/// ```
///
/// ## Signature verification
///
/// When no verifier is explicit specified, the default is chosen based on the enabled crate features:
///
/// | Features        | Description                                |
/// |-----------------|--------------------------------------------|
/// | `[]`            | No signature verification of data          |
/// | `ring_verifier` | Uses the `ring` crate to verify signatures |
///
/// See [`Verification`] for implementing a custom signature verifier.
pub struct Client {
    server_url: String,
    bucket_name: String,
    collection_name: String,
    // Box<dyn Trait> is necessary since implementation of [`Verification`] can be of any size unknown at compile time
    verifier: Box<dyn Verification>,
    storage: Box<dyn Storage>,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            bucket_name: DEFAULT_BUCKET_NAME.to_owned(),
            collection_name: "".to_owned(),
            verifier: Box::new(DefaultVerifier {}),
            storage: Box::new(DummyStorage {}),
        }
    }
}

impl Client {
    /// Creates a `ClientBuilder` to configure a `Client`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Return the records stored locally.
    ///
    /// # Examples
    /// ```rust
    /// # use remote_settings_client::Client;
    /// # use viaduct::set_backend;
    /// # pub use viaduct_reqwest::ReqwestBackend;
    /// # fn main() {
    /// # set_backend(&ReqwestBackend).unwrap();
    /// # let mut client = Client::builder().collection_name("url-classifier-skip-urls").build();
    /// match client.get() {
    ///   Ok(records) => println!("{:?}", records),
    ///   Err(error) => println!("Error fetching/verifying records: {:?}", error)
    /// };
    /// # }
    /// ```
    ///
    /// # Behaviour
    /// * Return local data by default;
    /// * If local data is empty or malformed, and if `sync_if_empty` is `true` (*default*),
    ///   then synchronize the local data with the server and return records, otherwise
    ///   return an empty list.
    ///
    /// Note: with the [`DummyStorage`], any call to `.get()` will trigger a synchronization.
    ///
    /// Note: with `sync_if_empty` as `false`, if `.sync()` is never called then `.get()` will
    /// always return an empty list.
    ///
    /// # Errors
    /// If an error occurs while fetching or verifying records, a [`ClientError`] is returned.
    pub fn get(&mut self) -> Result<Vec<KintoObject>, ClientError> {
        let storage_key = format!("{}/{}:collection", self.bucket_name, self.collection_name);

        debug!("Retrieve from storage with key={:?}", storage_key);
        let stored_bytes: Vec<u8> = self
            .storage
            .retrieve(&storage_key)
            .unwrap_or(None)
            .unwrap_or_else(Vec::new);
        let stored: Option<Collection> = serde_json::from_slice(&stored_bytes).unwrap_or(None);

        match stored {
            // TODO: add `verifySignature` option to make sure local data was not tampered.
            Some(collection) => Ok(collection.records),
            // TODO: this empty list should be «qualified». Is it empty because never synced
            // or empty on the server too. (see Normandy suitabilities).
            // TODO: add `syncIfEmpty` option so that synchronization happens if local DB is empty.
            None => Ok(Vec::new()),
        }
    }

    /// Synchronize the local storage with the content of the server for this collection.
    ///
    /// # Behaviour
    /// * If stored data is up-to-date and signature of local data valid, then return local content;
    /// * Otherwise fetch content from server, merge with local content, verify signature, and return records;
    ///
    /// # Errors
    /// If an error occurs while fetching or verifying records, a [`ClientError`] is returned.
    pub fn sync<T>(&mut self, expected: T) -> Result<Collection, ClientError>
    where
        T: Into<Option<u64>>,
    {
        let storage_key = format!("{}/{}:collection", self.bucket_name, self.collection_name);

        debug!("Retrieve from storage with key={:?}", storage_key);
        let stored_bytes: Vec<u8> = self
            .storage
            .retrieve(&storage_key)
            .unwrap_or(None)
            .unwrap_or_else(Vec::new);
        let stored: Option<Collection> = serde_json::from_slice(&stored_bytes).unwrap_or(None);

        let remote_timestamp = match expected.into() {
            Some(v) => v,
            None => {
                debug!("Obtain current timestamp.");
                get_latest_change_timestamp(
                    &self.server_url,
                    &self.bucket_name,
                    &self.collection_name,
                )?
            }
        };

        if let Some(ref collection) = stored {
            let up_to_date = collection.timestamp == remote_timestamp;
            if up_to_date && self.verifier.verify(&collection).is_ok() {
                debug!("Local data is up-to-date and valid.");
                return Ok(collection.to_owned());
            }
        }

        info!("Local data is empty, outdated, or has been tampered. Fetch from server.");
        let (local_records, local_timestamp) = match stored {
            Some(c) => (c.records, Some(c.timestamp)),
            None => (Vec::new(), None),
        };

        let changeset = get_changeset(
            &self.server_url,
            &self.bucket_name,
            &self.collection_name,
            Some(remote_timestamp),
            local_timestamp,
        )?;

        debug!(
            "Apply {} changes to {} local records",
            changeset.changes.len(),
            local_records.len()
        );
        let merged = merge_changes(local_records.to_vec(), changeset.changes);

        let collection = Collection {
            bid: self.bucket_name.to_owned(),
            cid: self.collection_name.to_owned(),
            metadata: changeset.metadata,
            records: merged,
            timestamp: changeset.timestamp,
        };

        debug!("Verify signature after merge of changes with previous local data.");
        self.verifier.verify(&collection)?;

        debug!("Store collection with key={:?}", storage_key);
        let collection_bytes: Vec<u8> = serde_json::to_string(&collection)?.into();
        self.storage.store(&storage_key, collection_bytes)?;

        Ok(collection)
    }
}

fn merge_changes(
    local_records: Vec<KintoObject>,
    remote_changes: Vec<KintoObject>,
) -> Vec<KintoObject> {
    // Merge changes by record id and delete tombstones.
    let mut local_by_id: HashMap<String, KintoObject> = HashMap::new();
    for record in local_records {
        local_by_id.insert(record["id"].to_string(), record);
    }
    for change in remote_changes.iter().rev() {
        let id = change["id"].to_string();
        if change
            .get("deleted")
            .unwrap_or(&json!(false))
            .as_bool()
            .unwrap_or(false)
        {
            local_by_id.remove(&id);
        } else {
            local_by_id.insert(id, change.to_owned());
        }
    }

    local_by_id
        .values()
        .map(|v| v.to_owned())
        .collect::<Vec<KintoObject>>()
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::signatures::{SignatureError, Verification};
    use super::{Client, ClientError, Collection, MemoryStorage};
    use env_logger;
    use httpmock::Method::GET;
    use httpmock::{Mock, MockServer};
    use viaduct::set_backend;
    use viaduct_reqwest::ReqwestBackend;

    struct VerifierWithNoError {}
    struct VerifierWithInvalidSignatureError {}

    impl Verification for VerifierWithNoError {
        fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
            Ok(())
        }
    }

    impl Verification for VerifierWithInvalidSignatureError {
        fn verify(&self, _collection: &Collection) -> Result<(), SignatureError> {
            return Err(SignatureError::InvalidSignature {
                name: "invalid signature error from tests".to_owned(),
            });
        }
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
        let _ = set_backend(&ReqwestBackend);
    }

    fn mock_json() -> Mock {
        Mock::new()
            .expect_method(GET)
            .return_status(200)
            .return_header("Content-Type", "application/json")
    }

    #[test]
    fn test_get_empty_storage() {
        init();

        let mut client = Client::builder()
            .collection_name("url-classifier-skip-urls")
            .build();

        assert_eq!(client.get().unwrap().len(), 0);
    }

    #[test]
    fn test_get_bad_stored_data() {
        init();

        let mut client = Client::builder().collection_name("cfr").build();

        client.storage.store("main/cfr", b"abc".to_vec()).unwrap();

        assert_eq!(client.get().unwrap().len(), 0);
    }

    #[test]
    fn test_get_with_empty_records_list() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_json()
            .expect_path("/buckets/main/collections/regions/changeset")
            .expect_query_param("_expected", "42")
            .return_body(
                r#"{
                    "metadata": {},
                    "changes": [],
                    "timestamp": 0
                }"#,
            )
            .create_on(&mock_server);

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .collection_name("regions")
            .verifier(Box::new(VerifierWithNoError {}))
            .build();

        client.sync(42).unwrap();

        assert_eq!(client.get().unwrap().len(), 0);

        assert_eq!(1, get_changeset_mock.times_called());
        get_changeset_mock.delete();
    }

    #[test]
    fn test_get_return_previously_synced_records() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_json()
            .expect_path("/buckets/main/collections/blocklist/changeset")
            .expect_query_param("_expected", "123")
            .return_body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 123,
                        "foo": "bar"
                    }],
                    "timestamp": 123
                }"#,
            )
            .create_on(&mock_server);

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .collection_name("blocklist")
            .storage(Box::new(MemoryStorage::new()))
            .verifier(Box::new(VerifierWithNoError {}))
            .build();

        client.sync(123).unwrap();

        let records = client.get().unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["foo"].as_str().unwrap(), "bar");

        assert_eq!(1, get_changeset_mock.times_called());
        get_changeset_mock.delete();
    }

    #[test]
    fn test_sync_pulls_current_timestamp_from_changes_endpoint_if_none() {
        init();

        let mock_server = MockServer::start();
        let mut get_latest_change_mock = mock_json()
            .expect_path("/buckets/monitor/collections/changes/changeset")
            .return_body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "not-read",
                        "last_modified": 123,
                        "bucket": "main",
                        "collection": "fxmonitor"
                    }],
                    "timestamp": 42
                }"#,
            )
            .create_on(&mock_server);

        let mut get_changeset_mock = mock_json()
            .expect_path("/buckets/main/collections/fxmonitor/changeset")
            .expect_query_param("_expected", "123")
            .return_body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 555,
                        "foo": "bar"
                    }],
                    "timestamp": 555
                }"#,
            )
            .create_on(&mock_server);

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .collection_name("fxmonitor")
            .verifier(Box::new(VerifierWithNoError {}))
            .build();

        client.sync(None).unwrap();

        assert_eq!(1, get_changeset_mock.times_called());
        assert_eq!(1, get_latest_change_mock.times_called());
        get_changeset_mock.delete();
        get_latest_change_mock.delete();
    }

    #[test]
    fn test_sync_uses_specified_expected_parameter() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_json()
            .expect_path("/buckets/main/collections/pioneers/changeset")
            .expect_query_param("_expected", "13")
            .return_body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 13,
                        "foo": "bar"
                    }],
                    "timestamp": 13
                }"#,
            )
            .create_on(&mock_server);

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .collection_name("pioneers")
            .verifier(Box::new(VerifierWithNoError {}))
            .build();

        client.sync(13).unwrap();

        assert_eq!(1, get_changeset_mock.times_called());
        get_changeset_mock.delete();
    }

    #[test]
    fn test_sync_fails_with_unknown_collection() {
        init();

        let mock_server = MockServer::start();
        let mut get_latest_change_mock = mock_json()
            .expect_path("/buckets/monitor/collections/changes/changeset")
            .return_body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "not-read",
                        "last_modified": 123,
                        "bucket": "main",
                        "collection": "fxmonitor"
                    }],
                    "timestamp": 42
                }"#,
            )
            .create_on(&mock_server);

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .collection_name("url-classifier-skip-urls")
            .build();

        let err = client.sync(None).unwrap_err();
        assert_eq!(
            err,
            ClientError::Error {
                name: format!(
                    "Unknown collection {}/{}",
                    "main", "url-classifier-skip-urls"
                ),
            }
        );

        assert_eq!(1, get_latest_change_mock.times_called());
        get_latest_change_mock.delete();
    }

    #[test]
    fn test_sync_uses_x5u_from_metadata_to_verify_signatures() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_json()
            .expect_path("/buckets/main/collections/onecrl/changeset")
            .expect_query_param("_expected", "42")
            .return_body(
                r#"{
                    "metadata": {
                        "missing": "x5u"
                    },
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 13,
                        "foo": "bar"
                    }],
                    "timestamp": 13
                }"#,
            )
            .create_on(&mock_server);

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .collection_name("onecrl")
            // With default verifier.
            .build();

        let err = client.sync(42).unwrap_err();

        assert_eq!(
            err,
            ClientError::VerificationError {
                name: "x5u field not present in signature".to_owned()
            }
        );

        assert_eq!(1, get_changeset_mock.times_called());
        get_changeset_mock.delete();
    }
    #[test]
    fn test_sync_wraps_signature_errors() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_json()
            .expect_path("/buckets/main/collections/password-recipes/changeset")
            .expect_query_param("_expected", "42")
            .return_body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 13,
                        "foo": "bar"
                    }],
                    "timestamp": 13
                }"#,
            )
            .create_on(&mock_server);

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .collection_name("password-recipes")
            .verifier(Box::new(VerifierWithInvalidSignatureError {}))
            .build();

        let err = client.sync(42).unwrap_err();
        assert_eq!(
            err,
            ClientError::VerificationError {
                name: "invalid signature error from tests".to_owned()
            }
        );

        assert_eq!(1, get_changeset_mock.times_called());
        get_changeset_mock.delete();
    }

    #[test]
    fn test_sync_returns_collection_with_merged_changes() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock_1 = mock_json()
            .expect_path("/buckets/main/collections/onecrl/changeset")
            .expect_query_param("_expected", "15")
            .return_body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 15
                    }, {
                        "id": "record-2",
                        "last_modified": 14,
                        "field": "before"
                    }, {
                        "id": "record-3",
                        "last_modified": 13
                    }],
                    "timestamp": 15
                }"#,
            )
            .create_on(&mock_server);

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .collection_name("onecrl")
            .storage(Box::new(MemoryStorage::new()))
            .verifier(Box::new(VerifierWithNoError {}))
            .build();

        let res = client.sync(15).unwrap();
        assert_eq!(res.records.len(), 3);

        assert_eq!(1, get_changeset_mock_1.times_called());
        get_changeset_mock_1.delete();

        let mut get_changeset_mock_2 = mock_json()
            .expect_path("/buckets/main/collections/onecrl/changeset")
            .expect_query_param("_since", "15")
            .expect_query_param("_expected", "42")
            .return_body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 42,
                        "field": "after"
                    }, {
                        "id": "record-4",
                        "last_modified": 30
                    }, {
                        "id": "record-2",
                        "last_modified": 20,
                        "delete": true
                    }],
                    "timestamp": 42
                }"#,
            )
            .create_on(&mock_server);

        let res = client.sync(42).unwrap();
        assert_eq!(res.records.len(), 4);

        let record_1_idx = res
            .records
            .iter()
            .position(|r| r["id"].as_str().unwrap() == "record-1")
            .unwrap();
        let record_1 = &res.records[record_1_idx];
        assert_eq!(record_1["field"].as_str().unwrap(), "after");

        assert_eq!(1, get_changeset_mock_2.times_called());
        get_changeset_mock_2.delete();
    }
}
