//! Strict typed request sidecars for authorized secure actions.

mod request;

pub use request::{Action, Error, Parameters, Request, MAX_REQUEST_BYTES};
