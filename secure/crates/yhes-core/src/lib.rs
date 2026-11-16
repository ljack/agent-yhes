//! Private state and MLS engine for the signed agent-yhes profile.
//! No private-state export API is exposed to transports or harnesses.
pub mod engine;
pub mod git;
pub mod keys;
pub mod local;
mod mls;
mod packet;
pub mod pilot;
pub mod store;
pub mod trust;
pub use packet::{Control, SignedContent};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("protected store operation failed")]
    Storage,
    #[error("vault committed locally; reopen to publish the checkpoint before retrying")]
    CheckpointPending,
    #[error("key provider unavailable: {0}")]
    KeyProvider(String),
    #[error("MLS operation rejected")]
    Mls,
}

pub type Result<T> = std::result::Result<T, Error>;
