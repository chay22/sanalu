use thiserror::Error;

#[derive(Error, Debug)]
pub enum SanaluError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Firewall error: {0}")]
    Firewall(String),

    #[error("Intelligence error: {0}")]
    Intelligence(String),

    #[error("Geo database error: {0}")]
    Geo(String),

    #[error("Cloudflare error: {0}")]
    Cloudflare(String),

    #[error("Parser error: {0}")]
    Parser(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<redb::Error> for SanaluError {
    fn from(err: redb::Error) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<redb::DatabaseError> for SanaluError {
    fn from(err: redb::DatabaseError) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<redb::TransactionError> for SanaluError {
    fn from(err: redb::TransactionError) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<redb::TableError> for SanaluError {
    fn from(err: redb::TableError) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<redb::StorageError> for SanaluError {
    fn from(err: redb::StorageError) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<redb::CommitError> for SanaluError {
    fn from(err: redb::CommitError) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<toml::de::Error> for SanaluError {
    fn from(err: toml::de::Error) -> Self {
        Self::Config(err.to_string())
    }
}

impl From<regex::Error> for SanaluError {
    fn from(err: regex::Error) -> Self {
        Self::Intelligence(err.to_string())
    }
}
