/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod kinto_http;
mod signatures;
mod storage;

use log::{debug, info};
use std::collections::HashMap;
use std::time::Duration;

#[cfg(test)]
use mock_instant::Instant;

#[cfg(not(test))]
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use kinto_http::{get_changeset, get_latest_change_timestamp, KintoError, KintoObject};
pub use signatures::{SignatureError, Verification};
pub use storage::{
    dummy_storage::DummyStorage, file_storage::FileStorage, memory_storage::MemoryStorage, Storage,
    StorageError,
};

#[cfg(feature = "ring_verifier")]
pub use crate::client::signatures::ring_verifier::RingVerifier;

#[cfg(feature = "rc_crypto_verifier")]
pub use crate::client::signatures::rc_crypto_verifier::RcCryptoVerifier;

use crate::client::signatures::dummy_verifier::DummyVerifier;

pub const DEFAULT_SERVER_URL: &str = "https://firefox.settings.services.mozilla.com/v1";
pub const DEFAULT_BUCKET_NAME: &str = "main";
pub const DEFAULT_SIGNER_NAME: &str = "remote-settings.content-signature.mozilla.org";
pub const PROD_CERT_ROOT_HASH: &str = "97:E8:BA:9C:F1:2F:B3:DE:53:CC:42:A4:E6:57:7E:D6:4D:F4:93:C2:47:B4:14:FE:A0:36:81:8D:38:23:56:0E";

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("content signature could not be verified: {0}")]
    IntegrityError(#[from] SignatureError),
    #[error("storage I/O error: {0}")]
    StorageError(#[from] StorageError),
    #[error("API failure: {0}")]
    APIError(#[from] KintoError),
    #[error("server indicated client to backoff ({0} secs remaining)")]
    BackoffError(u64),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Record(serde_json::Value);

impl Record {
    pub fn new(value: serde_json::Value) -> Record {
        Record(value)
    }

    // Return the underlying [`serde_json::Value`].
    pub fn as_object(&self) -> &serde_json::Map<String, serde_json::Value> {
        // Record data is always an object.
        &self.0.as_object().unwrap()
    }

    // Return the record id.
    pub fn id(&self) -> &str {
        // `id` field is always present as a string.
        self.0["id"].as_str().unwrap()
    }

    // Return the record timestamp.
    pub fn last_modified(&self) -> u64 {
        // `last_modified` field is always present as a uint.
        self.0["last_modified"].as_u64().unwrap()
    }

    // Return true if the record is a tombstone.
    pub fn deleted(&self) -> bool {
        match self.get("deleted") {
            Some(v) => v.as_bool().unwrap_or(false),
            None => false,
        }
    }

    // Return a field value.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }
}

impl<I> std::ops::Index<I> for Record
where
    I: serde_json::value::Index,
{
    type Output = serde_json::Value;
    fn index(&self, index: I) -> &serde_json::Value {
        static NULL: serde_json::Value = serde_json::Value::Null;
        index.index_into(&self.0).unwrap_or(&NULL)
    }
}

/// Representation of a collection on the server
#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
pub struct Collection {
    pub bid: String,
    pub cid: String,
    pub metadata: KintoObject,
    pub records: Vec<Record>,
    pub timestamp: u64,
    pub signer: String,
}

/// Client to fetch Remote Settings data.
///
/// # Examples
/// Create a `Client` for the `cid` collection on the production server:
/// ```rust
/// # use remote_settings_client::Client;
/// # fn main() {
/// let client = Client::builder()
///   .collection_name("cid")
///   .build()
///   .unwrap();
/// # }
/// ```
/// Or for a specific server or bucket:
/// ```rust
/// # use remote_settings_client::Client;
/// # fn main() {
/// let client = Client::builder()
///   .server_url("https://settings.stage.mozaws.net/v1")
///   .bucket_name("main-preview")
///   .collection_name("cid")
///   .build()
///   .unwrap();
/// # }
/// ```
///
/// ## Signature verification
///
/// When no verifier is explicitly specified, a dummy verifier is used.
///
/// ### `ring`
///
/// With the `ring_verifier` feature, a signature verifier leveraging the [`ring` crate](https://crates.io/crates/ring).
/// ```rust
/// # #[cfg(feature = "ring_verifier")] {
/// # use remote_settings_client::Client;
/// use remote_settings_client::RingVerifier;
///
/// let client = Client::builder()
///   .collection_name("cid")
///   .verifier(Box::new(RingVerifier {}))
///   .build()
///   .unwrap();
/// # }
/// ```
///
/// ### `rc_crypto`
///
/// With the `rc_crypto` feature, a signature verifier leveraging the [`rc_crypto` crate](https://github.com/mozilla/application-services/tree/v73.0.2/components/support/rc_crypto).
/// ```rust
/// # #[cfg(feature = "rc_crypto_verifier")] {
/// # use remote_settings_client::Client;
/// use remote_settings_client::RcCryptoVerifier;
///
/// let client = Client::builder()
///   .collection_name("cid")
///   .verifier(Box::new(RcCryptoVerifier {}))
///   .build()
///   .unwrap();
/// # }
/// ```
/// In order to use it, the NSS library must be available.
/// ```text
/// export NSS_DIR=/path/to/nss
/// export NSS_STATIC=1
///
/// cargo build --features=rc_crypto_verifier
/// ```
/// See [detailed NSS installation instructions](https://github.com/mozilla-services/remote-settings-client/blob/747e881/.circleci/config.yml#L25-L46).
///
/// ### Custom
/// See [`Verification`] for implementing a custom signature verifier.
///
#[derive(Builder, Debug)]
#[builder(pattern = "owned")] // No clone because of Box<dyn...>
pub struct Client {
    #[builder(setter(into), default = "DEFAULT_SERVER_URL.to_owned()")]
    server_url: String,
    #[builder(setter(into), default = "DEFAULT_BUCKET_NAME.to_owned()")]
    bucket_name: String,
    #[builder(setter(into))]
    collection_name: String,
    #[builder(setter(into), default = "DEFAULT_SIGNER_NAME.to_owned()")]
    signer_name: String,
    // Box<dyn Trait> is necessary since implementation of [`Verification`] can be of any size unknown at compile time
    #[builder(default = "Box::new(DummyVerifier {})")]
    verifier: Box<dyn Verification>,
    #[builder(default = "Box::new(DummyStorage {})")]
    storage: Box<dyn Storage>,
    #[builder(default = "true")]
    sync_if_empty: bool,
    #[builder(default = "true")]
    trust_local: bool,
    #[builder(private, default = "None")]
    backoff_until: Option<Instant>,
    #[builder(default = "PROD_CERT_ROOT_HASH.to_owned()")]
    cert_root_hash: String,
}

impl Default for Client {
    fn default() -> Self {
        Client::builder().build().unwrap()
    }
}

impl std::fmt::Debug for Box<dyn Verification> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Box<dyn Verification>")
    }
}

impl std::fmt::Debug for Box<dyn Storage> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Box<dyn Storage>")
    }
}

impl Client {
    /// Creates a `ClientBuilder` to configure a `Client`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    pub fn _storage_key(&self) -> String {
        format!("{}/{}:collection", self.bucket_name, self.collection_name)
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
    /// # let mut client = Client::builder().collection_name("url-classifier-skip-urls").build().unwrap();
    /// match client.get() {
    ///   Ok(records) => println!("{:?}", records),
    ///   Err(error) => println!("Error fetching/verifying records: {:?}", error)
    /// };
    /// # }
    /// ```
    ///
    /// # Behaviour
    /// * Return local data by default;
    /// * If local data is empty and if `sync_if_empty` is `true` (*default*),
    ///   then synchronize the local data with the server and return records, otherwise
    ///   return an error.
    ///
    /// Note: with the [`DummyStorage`], any call to `.get()` will trigger a synchronization.
    ///
    /// Note: with `sync_if_empty` as `false`, if `.sync()` is never called then `.get()` will
    /// always return an error.
    ///
    /// # Errors
    /// If an error occurs while fetching or verifying records, a [`ClientError`] is returned.
    pub fn get(&mut self) -> Result<Vec<Record>, ClientError> {
        let storage_key = self._storage_key();

        debug!("Retrieve from storage with key={:?}", storage_key);
        let read_result = self.storage.retrieve(&storage_key);

        match read_result {
            Ok(stored_bytes) => {
                // Deserialize content of storage and surface error if fails.
                let stored: Collection = serde_json::from_slice(&stored_bytes).map_err(|err| {
                    StorageError::ReadError(format!("cannot deserialize collection: {}", err))
                })?;
                // Verify signature of stored data (*optional*)
                if !self.trust_local {
                    debug!("Verify signature of local data.");
                    self.verifier.verify(&stored, &self.cert_root_hash)?;
                }

                Ok(stored.records)
            }
            // If storage is empty, go on with sync() (*optional*)
            Err(StorageError::KeyNotFound { .. }) if self.sync_if_empty => {
                debug!("Synchronize data, without knowning which timestamp to expect.");
                let collection = self.sync(None)?;
                Ok(collection.records)
            }
            // Otherwise, surface the error.
            Err(err) => Err(err.into()),
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
        self.check_sync_state()?;

        let storage_key = self._storage_key();

        debug!("Retrieve from storage with key={:?}", storage_key);
        let stored_bytes: Vec<u8> = self.storage.retrieve(&storage_key).unwrap_or_default();
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
            if up_to_date
                && self
                    .verifier
                    .verify(&collection, &self.cert_root_hash)
                    .is_ok()
            {
                debug!("Local data is up-to-date and valid.");
                return Ok(stored.unwrap());
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
            remote_timestamp,
            local_timestamp,
        )?;

        // Keep in state that the server indicated the client
        // to backoff for a while.
        if let Some(backoff_secs) = changeset.backoff {
            self.backoff_until = Some(Instant::now() + Duration::from_secs(backoff_secs));
        }

        debug!(
            "Apply {} changes to {} local records",
            changeset.changes.len(),
            local_records.len()
        );
        let merged = merge_changes(local_records, changeset.changes);

        let collection = Collection {
            bid: self.bucket_name.clone(),
            cid: self.collection_name.clone(),
            metadata: changeset.metadata,
            records: merged,
            timestamp: changeset.timestamp,
            signer: self.signer_name.clone(),
        };

        debug!("Verify signature after merge of changes with previous local data.");
        self.verifier.verify(&collection, &self.cert_root_hash)?;

        debug!("Store collection with key={:?}", storage_key);
        let collection_bytes: Vec<u8> = serde_json::to_string(&collection)
            .map_err(|err| {
                StorageError::WriteError(format!("cannot serialize collection: {}", err))
            })?
            .into();
        self.storage.store(&storage_key, collection_bytes)?;

        Ok(collection)
    }

    fn check_sync_state(&mut self) -> Result<(), ClientError> {
        if let Some(until) = self.backoff_until {
            if Instant::now() < until {
                let remaining_secs = (until - Instant::now()).as_secs();
                return Err(ClientError::BackoffError(remaining_secs));
            }
            self.backoff_until = None;
        }
        Ok(())
    }
}

fn merge_changes(local_records: Vec<Record>, remote_changes: Vec<KintoObject>) -> Vec<Record> {
    // Merge changes by record id and delete tombstones.
    let mut local_by_id: HashMap<String, Record> = local_records
        .into_iter()
        .map(|record| (record.id().into(), record))
        .collect();
    for entry in remote_changes.into_iter().rev() {
        let change = Record::new(entry);
        let id = change.id();
        if change.deleted() {
            local_by_id.remove(id);
        } else {
            local_by_id.insert(id.into(), change);
        }
    }

    local_by_id.into_iter().map(|(_, v)| v).collect()
}
#[cfg(test)]
mod tests {
    use super::signatures::{SignatureError, Verification};
    use super::{
        Client, ClientError, Collection, DummyStorage, DummyVerifier, MemoryStorage, Record,
    };
    use env_logger;
    use httpmock::MockServer;
    use serde_json::json;
    use std::time::Duration;
    use viaduct::set_backend;
    use viaduct_reqwest::ReqwestBackend;

    #[cfg(feature = "ring_verifier")]
    pub use crate::client::signatures::ring_verifier::RingVerifier;

    struct VerifierWithInvalidSignatureError {}

    impl Verification for VerifierWithInvalidSignatureError {
        fn verify_nist384p_chain(
            &self,
            _: u64,
            _: &[u8],
            _: &str,
            _: &str,
            _: &[u8],
            _: &[u8],
        ) -> Result<(), SignatureError> {
            Ok(()) // unreachable.
        }

        fn verify(&self, _collection: &Collection, _: &str) -> Result<(), SignatureError> {
            Err(SignatureError::MismatchError(
                "fake invalid signature".to_owned(),
            ))
        }
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
        let _ = set_backend(&ReqwestBackend);
    }

    #[test]
    fn test_fails_if_no_collection() {
        let err = Client::builder().build().unwrap_err();

        assert_eq!(err.to_string(), "`collection_name` must be initialized");
    }

    #[test]
    fn test_default_builder() {
        let client = Client::builder().collection_name("cid").build().unwrap();

        // Assert defaults for consumers.
        assert!(
            client.server_url.contains("services.mozilla.com"),
            "Unexpected server URL: {}",
            client.server_url
        );
        assert_eq!(client.bucket_name, "main");
        assert_eq!(client.sync_if_empty, true);
        assert_eq!(client.trust_local, true);
        // And Debug format
        assert_eq!(format!("{:?}", client), "Client { server_url: \"https://firefox.settings.services.mozilla.com/v1\", bucket_name: \"main\", collection_name: \"cid\", signer_name: \"remote-settings.content-signature.mozilla.org\", verifier: Box<dyn Verification>, storage: Box<dyn Storage>, sync_if_empty: true, trust_local: true, backoff_until: None, cert_root_hash: \"97:E8:BA:9C:F1:2F:B3:DE:53:CC:42:A4:E6:57:7E:D6:4D:F4:93:C2:47:B4:14:FE:A0:36:81:8D:38:23:56:0E\" }");
    }

    #[test]
    fn test_get_works_with_dummy_storage() {
        init();

        let mock_server = MockServer::start();
        let mut get_latest_change_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset")
                .query_param("_expected", "0");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "not-read",
                        "last_modified": 555,
                        "bucket": "main",
                        "collection": "top-sites"
                    }],
                    "timestamp": 555
                }"#,
            );
        });

        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/top-sites/changeset")
                .query_param("_expected", "555");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 555,
                        "foo": "bar"
                    }],
                    "timestamp": 555
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .collection_name("top-sites")
            .storage(Box::new(DummyStorage {}))
            .verifier(Box::new(DummyVerifier {}))
            .build()
            .unwrap();

        let records = client.get().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["foo"].as_str().unwrap(), "bar");

        get_changeset_mock.assert_hits(1);
        get_latest_change_mock.assert_hits(1);

        // Calling again will pull from network.
        let records_twice = client.get().unwrap();
        assert_eq!(records_twice.len(), 1);

        get_changeset_mock.assert_hits(2);
        get_latest_change_mock.assert_hits(2);

        get_changeset_mock.delete();
        get_latest_change_mock.delete();
    }

    #[test]
    fn test_get_with_empty_storage() {
        init();

        let mock_server = MockServer::start();
        let mut get_latest_change_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset")
                .query_param("_expected", "0");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "not-read",
                        "last_modified": 888,
                        "bucket": "main",
                        "collection": "pocket"
                    }],
                    "timestamp": 555
                }"#,
            );
        });

        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/pocket/changeset")
                .query_param("_expected", "888");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 888,
                        "foo": "bar"
                    }],
                    "timestamp": 555
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(&mock_server.url(""))
            .collection_name("pocket")
            .storage(Box::new(MemoryStorage::new()))
            .verifier(Box::new(DummyVerifier {}))
            .build()
            .unwrap();

        let records = client.get().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["foo"].as_str().unwrap(), "bar");

        get_changeset_mock.assert();
        get_latest_change_mock.assert();

        // Calling again won't pull from network.
        let records_twice = client.get().unwrap();
        assert_eq!(records_twice.len(), 1);

        get_changeset_mock.assert_hits(1);
        get_latest_change_mock.assert_hits(1);

        get_changeset_mock.delete();
        get_latest_change_mock.delete();
    }

    #[test]
    fn test_get_empty_storage_no_sync_if_empty() {
        init();
        let mock_server = MockServer::start();

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("url-classifier-skip-urls")
            // Explicitly disable sync if empty.
            .sync_if_empty(false)
            .build()
            .unwrap();

        let err = client.get().unwrap_err();
        assert_eq!(
            err.to_string(),
            "storage I/O error: key could not be found: main/url-classifier-skip-urls:collection"
        );
    }

    #[test]
    fn test_get_bad_stored_data() {
        init();
        let mock_server = MockServer::start();

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("cfr")
            .storage(Box::new(MemoryStorage::new()))
            .sync_if_empty(false)
            .build()
            .unwrap();

        client
            .storage
            .store("main/cfr:collection", b"abc".to_vec())
            .unwrap();

        let err = client.get().unwrap_err();
        assert_eq!(err.to_string(), "storage I/O error: cannot read from storage: cannot deserialize collection: expected value at line 1 column 1");
    }

    #[test]
    fn test_get_bad_stored_data_if_untrusted() {
        init();
        let mock_server = MockServer::start();

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("search-config")
            .storage(Box::new(MemoryStorage::new()))
            .verifier(Box::new(VerifierWithInvalidSignatureError {}))
            .sync_if_empty(false)
            .trust_local(false)
            .build()
            .unwrap();

        let collection = Collection {
            bid: "main".to_owned(),
            cid: "search-config".to_owned(),
            metadata: json!({}),
            records: vec![Record(json!({}))],
            timestamp: 42,
            signer: "some-name".to_owned(),
        };
        let collection_bytes: Vec<u8> = serde_json::to_string(&collection).unwrap().into();
        client
            .storage
            .store("main/search-config:collection", collection_bytes)
            .unwrap();

        let err = client.get().unwrap_err();
        assert_eq!(
            err.to_string(),
            "content signature could not be verified: signature mismatch: fake invalid signature"
        );
    }

    #[test]
    fn test_get_with_empty_records_list() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/regions/changeset")
                .query_param("_expected", "42");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [],
                    "timestamp": 0
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("regions")
            .storage(Box::new(MemoryStorage::new()))
            .build()
            .unwrap();

        client.sync(42).unwrap();

        assert_eq!(client.get().unwrap().len(), 0);

        get_changeset_mock.assert();
        get_changeset_mock.delete();
    }

    #[test]
    fn test_get_return_previously_synced_records() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/blocklist/changeset")
                .query_param("_expected", "123");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 123,
                        "foo": "bar"
                    }],
                    "timestamp": 123
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("blocklist")
            .storage(Box::new(MemoryStorage::new()))
            .build()
            .unwrap();

        client.sync(123).unwrap();

        let records = client.get().unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["foo"].as_str().unwrap(), "bar");

        get_changeset_mock.assert();
        get_changeset_mock.delete();
    }

    #[test]
    fn test_sync_pulls_current_timestamp_from_changes_endpoint_if_none() {
        init();

        let mock_server = MockServer::start();
        let mut get_latest_change_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset");
            then.body(
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
            );
        });

        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/fxmonitor/changeset")
                .query_param("_expected", "123");
            then.body(
                r#"{
                        "metadata": {},
                        "changes": [{
                            "id": "record-1",
                            "last_modified": 555,
                            "foo": "bar"
                        }],
                        "timestamp": 555
                    }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("fxmonitor")
            .build()
            .unwrap();

        client.sync(None).unwrap();

        get_changeset_mock.assert();
        get_latest_change_mock.assert();
        get_changeset_mock.delete();
        get_latest_change_mock.delete();
    }

    #[test]
    fn test_sync_uses_specified_expected_parameter() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/pioneers/changeset")
                .query_param("_expected", "13");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 13,
                        "foo": "bar"
                    }],
                    "timestamp": 13
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("pioneers")
            .build()
            .unwrap();

        client.sync(13).unwrap();

        get_changeset_mock.assert();
        get_changeset_mock.delete();
    }

    #[test]
    fn test_sync_fails_with_unknown_collection() {
        init();

        let mock_server = MockServer::start();
        let mut get_latest_change_mock = mock_server.mock(|when, then| {
            when.path("/buckets/monitor/collections/changes/changeset");
            then.body(
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
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("url-classifier-skip-urls")
            .build()
            .unwrap();

        let err = client.sync(None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "API failure: unknown collection: main/url-classifier-skip-urls",
        );

        get_latest_change_mock.assert();
        get_latest_change_mock.delete();
    }

    #[test]
    #[cfg(feature = "ring_verifier")]
    fn test_sync_uses_x5u_from_metadata_to_verify_signatures() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/onecrl/changeset")
                .query_param("_expected", "42");
            then.body(
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
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("onecrl")
            .verifier(Box::new(RingVerifier {}))
            .build()
            .unwrap();

        let err = client.sync(42).unwrap_err();

        assert_eq!(
            err.to_string(),
            "content signature could not be verified: signature payload has no x5u field"
        );

        get_changeset_mock.assert();
        get_changeset_mock.delete();
    }
    #[test]
    fn test_sync_wraps_signature_errors() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/password-recipes/changeset")
                .query_param("_expected", "42");
            then.body(
                r#"{
                    "metadata": {},
                    "changes": [{
                        "id": "record-1",
                        "last_modified": 13,
                        "foo": "bar"
                    }],
                    "timestamp": 13
                }"#,
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("password-recipes")
            .verifier(Box::new(VerifierWithInvalidSignatureError {}))
            .build()
            .unwrap();

        let err = client.sync(42).unwrap_err();
        assert_eq!(
            err.to_string(),
            "content signature could not be verified: signature mismatch: fake invalid signature"
        );

        get_changeset_mock.assert();
        get_changeset_mock.delete();
    }

    #[test]
    fn test_sync_returns_collection_with_merged_changes() {
        init();

        let mock_server = MockServer::start();
        let mut get_changeset_mock_1 = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/onecrl/changeset")
                .query_param("_expected", "15");
            then.body(
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
            );
        });

        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("onecrl")
            .storage(Box::new(MemoryStorage::new()))
            .build()
            .unwrap();

        let res = client.sync(15).unwrap();
        assert_eq!(res.records.len(), 3);

        get_changeset_mock_1.assert();
        get_changeset_mock_1.delete();

        let mut get_changeset_mock_2 = mock_server.mock(|when, then| {
            when.path("/buckets/main/collections/onecrl/changeset")
                .query_param("_since", "15")
                .query_param("_expected", "42");
            then.body(
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
            );
        });

        let res = client.sync(42).unwrap();
        assert_eq!(res.records.len(), 4);

        let record_1_idx = res
            .records
            .iter()
            .position(|r| r.id() == "record-1")
            .unwrap();
        let record_1 = &res.records[record_1_idx];
        assert_eq!(record_1["field"].as_str().unwrap(), "after");

        get_changeset_mock_2.assert();
        get_changeset_mock_2.delete();
    }

    #[test]
    fn test_record_fields() {
        let r = Record(json!({
            "id": "abc",
            "last_modified": 100,
            "foo": {"bar": 42},
            "pi": "3.14"
        }));

        assert_eq!(r.id(), "abc");
        assert_eq!(r.last_modified(), 100);
        assert_eq!(r.deleted(), false);

        // Access fields by index
        assert_eq!(r["pi"].as_str(), Some("3.14"));
        assert_eq!(r["foo"]["bar"].as_u64(), Some(42));
        assert_eq!(r["bar"], serde_json::Value::Null);

        // Or by get() as optional value
        assert_eq!(r.get("bar"), None);
        assert_eq!(r.get("pi").unwrap().as_str(), Some("3.14"));
        assert_eq!(r.get("pi").unwrap().as_f64(), None);
        assert_eq!(r.get("foo").unwrap().get("bar").unwrap().as_u64(), Some(42));

        let r = Record(json!({
            "id": "abc",
            "last_modified": 100,
            "deleted": true
        }));
        assert_eq!(r.deleted(), true);

        let r = Record(json!({
            "id": "abc",
            "last_modified": 100,
            "deleted": "foo"
        }));
        assert_eq!(r.deleted(), false);
    }

    #[test]
    fn test_backoff() {
        init();

        let mock_server = MockServer::start();
        let get_changeset_mocks: Vec<_> = [777, 888]
            .iter()
            .map(|&expected| {
                mock_server.mock(|when, then| {
                    when.path("/buckets/main/collections/nimbus/changeset")
                        .query_param("_expected".into(), format!("{}", expected));
                    then.header("Backoff", "300").json_body(json!(
                        {
                            "metadata": {},
                            "changes": [{
                                "id": "record-1",
                                "last_modified": expected
                            }],
                            "timestamp": expected
                        }
                    ));
                })
            })
            .collect();
        let mut client = Client::builder()
            .server_url(mock_server.url(""))
            .collection_name("nimbus")
            .build()
            .unwrap();

        client.sync(777).unwrap();
        let second_sync = client.sync(888).unwrap_err();
        mock_instant::MockClock::advance(Duration::from_secs(600));
        client.sync(888).unwrap();

        assert!(matches!(second_sync, ClientError::BackoffError(_)));
        for mut mock in get_changeset_mocks {
            mock.assert();
            mock.delete();
        }
    }
}
