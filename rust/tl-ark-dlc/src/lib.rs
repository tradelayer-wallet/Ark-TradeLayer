//! # tl-ark-dlc (EXPERIMENTAL)
//!
//! Isolated, experimental Rust port of the Ark/DLC logic in `Ark-TradeLayer`:
//! fail-closed configuration, typed storage records with an in-memory store, event witnesses,
//! DLC-style oracle attestations with event binding / announced-R binding / single-use nonces,
//! the collateralized VTXO loan lifecycle, and the TradeLayer VTXO handshake as a state machine.
//!
//! Experimental means: not audited, not wired to any network, synthetic keys only, interfaces may
//! change. See the README for the compatibility table and the Lean 4 theorems.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attestation;
pub mod config;
pub mod error;
pub mod handshake;
pub mod hash;
pub mod keys;
pub mod legacy;
pub mod loan;
pub mod storage;
pub mod util;
pub mod witness;

pub use error::{Error, Result};
