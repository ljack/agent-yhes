//! Two-person, explicitly pinned Git onboarding. The local pilot is separate.
mod config;
mod handshake;
mod messages;
mod registry;

pub use config::{open, TeamPin, TeamSession};
pub use handshake::{admit, connect, init, request};
pub use messages::{inbox, prepare_message, present, send, status, PreparedMessage};
pub use registry::sync;

use crate::Failure;
fn rejected() -> Failure {
    Failure::new(
        "team_evidence_rejected",
        "the team identity evidence does not match its pinned scope or keys",
    )
}
