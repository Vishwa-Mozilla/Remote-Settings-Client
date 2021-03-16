pub mod dummy_storage;
pub mod file_storage;
pub mod memory_storage;

/// A trait for giving a type a custom storage implementation
///
/// The `Storage` is used to store the collection content locally.
/// # How can I implement ```Storage```?
/// ```rust
/// # use remote_settings_client::{SignatureError, Verification, Storage, StorageError};
/// # use remote_settings_client::client::Collection;
/// struct MyStore {}
///
/// impl Storage for MyStore {
///     fn store(&mut self, key: &str, value: Vec<u8>) -> Result<(), StorageError> {
///         Ok(())
///     }
///
///     fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
///         Ok(Some(Vec::new()))
///     }
/// }
/// ```
pub trait Storage {
    /// Store a key, value pair.
    ///
    /// # Errors
    /// If an error occurs while storing, ```StorageError::Error``` is returned
    fn store(&mut self, key: &str, value: Vec<u8>) -> Result<(), StorageError>;

    /// Retrieve a value for a given key.
    ///
    /// # Errors
    /// If the key cannot be found, ```StorageError::ReadError``` is returned
    fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;
}

#[derive(Debug, PartialEq)]
pub enum StorageError {
    Error { name: String },
    ReadError { name: String },
}