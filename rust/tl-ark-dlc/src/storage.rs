//! Typed storage records and the persistence boundary.
//!
//! Source: `vtxo-loan-system/src/storage/schemas.ts` (Mongoose schemas). The Mongo/Redis I/O is
//! replaced by the [`Store`] trait; [`MemoryStore`] is the in-memory implementation used by tests.
//!
//! Unique constraints preserved from the legacy indexes: `eventId`, `announcementHash`,
//! `attestationId`, `loanId` and (critically) every nonce commitment `rValue` is unique across all
//! announcements. Additions: a single-writer [`WriterToken`] fenced by an epoch, and a per-nonce
//! state that moves `Fresh -> Used` atomically **before** any signature is produced.

use std::collections::{BTreeMap, BTreeSet};

use crate::attestation::Announcement;
use crate::error::{Error, Result};
use crate::loan::{Funding, LoanStatus};

/// Upper bound on stored records of each kind in [`MemoryStore`].
pub const MAX_RECORDS: usize = 100_000;

/// Kind of event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    /// Numeric (digit decomposition).
    Numeric,
    /// Binary.
    Binary,
    /// Enumerated.
    Enum,
}

/// `EventAnnouncement` document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventAnnouncementRecord {
    /// The signed announcement (event id, oracle key, descriptor, maturity, R values, signature).
    pub announcement: Announcement,
    /// Digest of the announcement body (`announcementHash`).
    pub announcement_hash: [u8; 32],
    /// Set once, after the attestation is recorded (`attestationId`).
    pub attestation_id: Option<String>,
}

/// `AttestationRecord` document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationRecord {
    /// Unique id.
    pub attestation_id: String,
    /// Event id.
    pub event_id: String,
    /// Oracle key.
    pub oracle_pubkey: [u8; 32],
    /// Attested outcomes.
    pub outcomes: Vec<String>,
    /// One 64-byte Schnorr signature per outcome.
    pub signatures: Vec<[u8; 64]>,
    /// Attestation time (unix seconds).
    pub attestation_time: u64,
    /// Verified against the announcement before being stored.
    pub verified: bool,
}

/// Contract type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractType {
    /// Collateralized.
    Collateralized,
    /// Unsecured (record only; accounting not ported).
    Unsecured,
    /// Custom.
    Custom,
}

/// `LoanContract` document (typed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoanRecord {
    /// Unique loan id.
    pub loan_id: String,
    /// Contract type.
    pub contract_type: ContractType,
    /// Lender key.
    pub lender_pubkey: [u8; 32],
    /// Borrower key.
    pub borrower_pubkey: [u8; 32],
    /// ASP key.
    pub server_pubkey: [u8; 32],
    /// Oracle key.
    pub oracle_pubkey: [u8; 32],
    /// Terms hash.
    pub terms_hash: [u8; 32],
    /// Principal (sats).
    pub principal_amount: u64,
    /// Collateral (sats).
    pub collateral_amount: Option<u64>,
    /// Interest (sats).
    pub interest_amount: u64,
    /// Maturity (unix seconds).
    pub maturity_time: u64,
    /// Repayment deadline (unix seconds).
    pub repayment_deadline: u64,
    /// Oracle event ids.
    pub repayment_event_id: Option<String>,
    /// Oracle event ids.
    pub price_event_id: Option<String>,
    /// Oracle event ids.
    pub other_event_ids: Vec<String>,
    /// Funding outpoint.
    pub funding: Option<Funding>,
    /// VTXO locking script.
    pub locking_script: Vec<u8>,
    /// Exit delay (blocks).
    pub exit_delay: u32,
    /// Status.
    pub status: LoanStatus,
    /// Settlement txid.
    pub settlement_txid: Option<[u8; 32]>,
    /// Settlement outcome label.
    pub settlement_outcome: Option<String>,
}

/// Witness kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessType {
    /// Payment.
    Payment,
    /// Threshold.
    Threshold,
    /// Time.
    Time,
    /// Composite.
    Composite,
}

/// `WitnessCheckLog` document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessLogRecord {
    /// Event id.
    pub event_id: String,
    /// Witness type.
    pub witness_type: WitnessType,
    /// Whether the condition was met.
    pub condition_met: bool,
    /// Witness data as text (legacy: arbitrary JSON).
    pub witness_data: String,
    /// Data source.
    pub source: String,
    /// Confidence in basis points (legacy: float 0..1).
    pub confidence_bps: Option<u16>,
    /// Check time (unix seconds).
    pub checked_at: u64,
}

/// State of one signing nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceState {
    /// Announced, never used.
    Fresh,
    /// Reserved/used for exactly this message digest. Never goes back to `Fresh`.
    Used {
        /// Digest of the one message this nonce signs.
        digest: [u8; 32],
    },
}

/// Persisted nonce record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceRecord {
    /// Announced nonce point (x-only).
    pub r: [u8; 32],
    /// State.
    pub state: NonceState,
}

/// One nonce consumption request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceUse {
    /// Outcome index.
    pub index: u32,
    /// Announced R expected for that index.
    pub r: [u8; 32],
    /// Digest of the message that will be signed.
    pub digest: [u8; 32],
}

/// Fencing token of the single writer. Every mutating nonce/attestation call must present the
/// current token; acquiring a new one invalidates all older tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterToken {
    epoch: u64,
}

/// Persistence boundary. Mutating methods take `&mut self`; implementations must make each call
/// atomic and durable before returning `Ok` (the oracle signs only after `begin_use` returned).
pub trait Store {
    /// Become the single writer; invalidates every earlier token.
    fn acquire_writer(&mut self, owner: &str) -> Result<WriterToken>;
    /// Persist an announcement and its `Fresh` nonce records. Enforces all unique constraints.
    fn reserve_announcement(
        &mut self,
        token: &WriterToken,
        rec: EventAnnouncementRecord,
    ) -> Result<()>;
    /// Fetch an announcement.
    fn get_announcement(&self, event_id: &str) -> Result<Option<EventAnnouncementRecord>>;
    /// Fetch a nonce record.
    fn nonce(&self, event_id: &str, index: u32) -> Result<Option<NonceRecord>>;
    /// Atomically move every listed nonce `Fresh -> Used{digest}`; all-or-nothing.
    fn begin_use(&mut self, token: &WriterToken, event_id: &str, uses: &[NonceUse]) -> Result<()>;
    /// Persist the attestation and set the announcement's `attestation_id` (once).
    fn record_attestation(&mut self, token: &WriterToken, rec: AttestationRecord) -> Result<()>;
    /// Fetch an attestation.
    fn get_attestation(&self, attestation_id: &str) -> Result<Option<AttestationRecord>>;
    /// Insert a loan (unique `loan_id`).
    fn insert_loan(&mut self, rec: LoanRecord) -> Result<()>;
    /// Fetch a loan.
    fn get_loan(&self, loan_id: &str) -> Result<Option<LoanRecord>>;
    /// Compare-and-set a loan status along an allowed edge.
    fn cas_loan_status(&mut self, loan_id: &str, from: LoanStatus, to: LoanStatus) -> Result<()>;
    /// Append a witness log row.
    fn insert_witness_log(&mut self, rec: WitnessLogRecord) -> Result<()>;
    /// Witness log rows for an event, newest first.
    fn witness_logs(&self, event_id: &str) -> Result<Vec<WitnessLogRecord>>;
}

/// In-memory [`Store`] with failure injection for durability tests.
#[derive(Default, Debug)]
pub struct MemoryStore {
    announcements: BTreeMap<String, EventAnnouncementRecord>,
    hashes: BTreeSet<[u8; 32]>,
    nonces: BTreeMap<(String, u32), NonceRecord>,
    r_index: BTreeSet<[u8; 32]>,
    attestations: BTreeMap<String, AttestationRecord>,
    loans: BTreeMap<String, LoanRecord>,
    witness: Vec<WitnessLogRecord>,
    epoch: u64,
    owner: Option<String>,
    /// Test hook: `begin_use` fails with a storage error without changing state.
    pub fail_begin_use: bool,
    /// Test hook: `record_attestation` fails with a storage error without changing state.
    pub fail_record_attestation: bool,
}

impl MemoryStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current writer owner label (diagnostics).
    pub fn writer_owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    fn check(&self, t: &WriterToken) -> Result<()> {
        if t.epoch == self.epoch && self.epoch != 0 {
            Ok(())
        } else {
            Err(Error::StaleWriter)
        }
    }
}

impl Store for MemoryStore {
    fn acquire_writer(&mut self, owner: &str) -> Result<WriterToken> {
        self.epoch = self.epoch.checked_add(1).ok_or(Error::Overflow)?;
        self.owner = Some(owner.to_string());
        Ok(WriterToken { epoch: self.epoch })
    }

    fn reserve_announcement(
        &mut self,
        token: &WriterToken,
        rec: EventAnnouncementRecord,
    ) -> Result<()> {
        self.check(token)?;
        let a = &rec.announcement;
        if self.announcements.len() >= MAX_RECORDS {
            return Err(Error::Capacity("announcements"));
        }
        if self.announcements.contains_key(&a.event_id) {
            return Err(Error::Duplicate("event id"));
        }
        if self.hashes.contains(&rec.announcement_hash) {
            return Err(Error::Duplicate("announcement hash"));
        }
        let mut seen = BTreeSet::new();
        for r in &a.nonce_points {
            if self.r_index.contains(r) || !seen.insert(*r) {
                return Err(Error::Duplicate("nonce commitment"));
            }
        }
        for (i, r) in a.nonce_points.iter().enumerate() {
            let idx = u32::try_from(i).map_err(|_| Error::Overflow)?;
            self.nonces.insert(
                (a.event_id.clone(), idx),
                NonceRecord {
                    r: *r,
                    state: NonceState::Fresh,
                },
            );
            self.r_index.insert(*r);
        }
        self.hashes.insert(rec.announcement_hash);
        self.announcements.insert(a.event_id.clone(), rec);
        Ok(())
    }

    fn get_announcement(&self, event_id: &str) -> Result<Option<EventAnnouncementRecord>> {
        Ok(self.announcements.get(event_id).cloned())
    }

    fn nonce(&self, event_id: &str, index: u32) -> Result<Option<NonceRecord>> {
        Ok(self.nonces.get(&(event_id.to_string(), index)).copied())
    }

    fn begin_use(&mut self, token: &WriterToken, event_id: &str, uses: &[NonceUse]) -> Result<()> {
        self.check(token)?;
        if self.fail_begin_use {
            return Err(Error::Storage("begin_use not persisted"));
        }
        // Phase 1: validate everything, mutate nothing.
        let mut idxs = BTreeSet::new();
        for u in uses {
            let reused = || Error::NonceReused {
                event_id: event_id.to_string(),
                index: u.index,
            };
            if !idxs.insert(u.index) {
                return Err(reused());
            }
            let rec = self
                .nonces
                .get(&(event_id.to_string(), u.index))
                .ok_or(Error::NotFound("nonce"))?;
            if rec.r != u.r {
                return Err(Error::RBindingMismatch { index: u.index });
            }
            if rec.state != NonceState::Fresh {
                return Err(reused());
            }
        }
        // Phase 2: commit.
        for u in uses {
            if let Some(rec) = self.nonces.get_mut(&(event_id.to_string(), u.index)) {
                rec.state = NonceState::Used { digest: u.digest };
            }
        }
        Ok(())
    }

    fn record_attestation(&mut self, token: &WriterToken, rec: AttestationRecord) -> Result<()> {
        self.check(token)?;
        if self.fail_record_attestation {
            return Err(Error::Storage("attestation not persisted"));
        }
        if self.attestations.len() >= MAX_RECORDS {
            return Err(Error::Capacity("attestations"));
        }
        if self.attestations.contains_key(&rec.attestation_id) {
            return Err(Error::Duplicate("attestation id"));
        }
        let ann = self
            .announcements
            .get_mut(&rec.event_id)
            .ok_or(Error::NotFound("announcement"))?;
        if ann.attestation_id.is_some() {
            return Err(Error::Duplicate("event already attested"));
        }
        ann.attestation_id = Some(rec.attestation_id.clone());
        self.attestations.insert(rec.attestation_id.clone(), rec);
        Ok(())
    }

    fn get_attestation(&self, attestation_id: &str) -> Result<Option<AttestationRecord>> {
        Ok(self.attestations.get(attestation_id).cloned())
    }

    fn insert_loan(&mut self, rec: LoanRecord) -> Result<()> {
        if self.loans.len() >= MAX_RECORDS {
            return Err(Error::Capacity("loans"));
        }
        if self.loans.contains_key(&rec.loan_id) {
            return Err(Error::Duplicate("loan id"));
        }
        self.loans.insert(rec.loan_id.clone(), rec);
        Ok(())
    }

    fn get_loan(&self, loan_id: &str) -> Result<Option<LoanRecord>> {
        Ok(self.loans.get(loan_id).cloned())
    }

    fn cas_loan_status(&mut self, loan_id: &str, from: LoanStatus, to: LoanStatus) -> Result<()> {
        let rec = self
            .loans
            .get_mut(loan_id)
            .ok_or(Error::NotFound("loan"))?;
        if rec.status != from {
            return Err(Error::Rejected("loan status changed concurrently"));
        }
        if !from.can_transition_to(to) {
            return Err(Error::IllegalTransition {
                from: from.name(),
                to: to.name(),
            });
        }
        rec.status = to;
        Ok(())
    }

    fn insert_witness_log(&mut self, rec: WitnessLogRecord) -> Result<()> {
        if self.witness.len() >= MAX_RECORDS {
            return Err(Error::Capacity("witness log"));
        }
        self.witness.push(rec);
        Ok(())
    }

    fn witness_logs(&self, event_id: &str) -> Result<Vec<WitnessLogRecord>> {
        let mut v: Vec<_> = self
            .witness
            .iter()
            .filter(|w| w.event_id == event_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.checked_at.cmp(&a.checked_at));
        Ok(v)
    }
}
