//! Event witnesses: decide whether an attestable condition holds.
//!
//! Source: `vtxo-loan-system/src/witness/event-witness.ts`. Differences: integer arithmetic only
//! (legacy used floating point and `Date.now()`), explicit clock, every client is a trait, and the
//! fail-open corners of the legacy code are closed:
//!
//! * `expectedAmount == 0` made `conditionMet` true with no payment (`totalReceived >= 0`);
//! * duplicate transfers from the client were summed twice, and transfers to other recipients or
//!   before `fromBlock` were trusted;
//! * a `CompositeWitness` with no children evaluated `every([]) == true` ("satisfied");
//! * price data for another symbol/currency or of any age was accepted.

use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::storage::{WitnessLogRecord, WitnessType};

/// Max transfers inspected per check.
pub const MAX_TRANSFERS: usize = 10_000;
/// Max children of a composite.
pub const MAX_CHILDREN: usize = 32;
/// Clock-skew allowance for price timestamps (seconds).
pub const MAX_FUTURE_SKEW_SECS: u64 = 60;

/// Result of one check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessResult {
    /// Whether the condition holds.
    pub condition_met: bool,
    /// Data source label.
    pub source: String,
    /// Confidence in basis points (0..=10000).
    pub confidence_bps: u16,
    /// Time of the check.
    pub timestamp: u64,
}

impl WitnessResult {
    /// Convert into an audit-log row.
    pub fn to_log(&self, event_id: &str, ty: WitnessType, data: String) -> WitnessLogRecord {
        WitnessLogRecord {
            event_id: event_id.to_string(),
            witness_type: ty,
            condition_met: self.condition_met,
            witness_data: data,
            source: self.source.clone(),
            confidence_bps: Some(self.confidence_bps),
            checked_at: self.timestamp,
        }
    }
}

/// Common witness behaviour.
pub trait Witness {
    /// Evaluate at time `now` (unix seconds).
    fn check(&self, now: u64) -> Result<WitnessResult>;
    /// Attestable outcome label.
    fn extract_outcome(&self, r: &WitnessResult) -> &'static str;
    /// Human readable description.
    fn describe(&self) -> String;
    /// Kind, for the audit log.
    fn witness_type(&self) -> WitnessType;
}

/// An observed transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    /// Sender.
    pub from: String,
    /// Recipient.
    pub to: String,
    /// Amount in atomic units.
    pub amount: u64,
    /// Transaction hash (dedup key).
    pub tx_hash: String,
    /// Block number.
    pub block_number: u64,
    /// Block timestamp.
    pub timestamp: u64,
}

/// Blockchain data source.
pub trait BlockchainClient {
    /// Transfers to `to_address` of `asset` from `from_block` on `network`.
    fn transfers(
        &self,
        network: &str,
        to_address: &str,
        asset: &str,
        from_block: u64,
    ) -> Result<Vec<Transfer>>;
}

/// Payment witness configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentConfig {
    /// Network label.
    pub network: String,
    /// Expected recipient.
    pub recipient: String,
    /// Expected amount in atomic units (> 0).
    pub expected_amount: u64,
    /// Asset label.
    pub asset: String,
    /// First block to consider.
    pub from_block: u64,
    /// Matching tolerance in basis points (legacy default 1% = 100).
    pub tolerance_bps: u32,
}

/// Payment witness.
pub struct PaymentWitness<C: BlockchainClient> {
    cfg: PaymentConfig,
    client: C,
}

impl<C: BlockchainClient> PaymentWitness<C> {
    /// Validate and build.
    pub fn new(cfg: PaymentConfig, client: C) -> Result<Self> {
        if cfg.expected_amount == 0 {
            return Err(Error::Rejected("expected amount must be positive"));
        }
        if cfg.tolerance_bps > 10_000 {
            return Err(Error::Rejected("tolerance above 100%"));
        }
        if cfg.recipient.is_empty() {
            return Err(Error::Rejected("recipient required"));
        }
        Ok(PaymentWitness { cfg, client })
    }
}

impl<C: BlockchainClient> Witness for PaymentWitness<C> {
    fn check(&self, now: u64) -> Result<WitnessResult> {
        let c = &self.cfg;
        let transfers = self
            .client
            .transfers(&c.network, &c.recipient, &c.asset, c.from_block)?;
        if transfers.len() > MAX_TRANSFERS {
            return Err(Error::TooLarge("transfers"));
        }
        let mut seen = BTreeSet::new();
        let mut total: u64 = 0;
        let mut matching = false;
        for t in &transfers {
            if t.to != c.recipient || t.block_number < c.from_block {
                continue;
            }
            if !seen.insert(t.tx_hash.clone()) {
                continue;
            }
            total = total.checked_add(t.amount).ok_or(Error::Overflow)?;
            let diff = u128::from(t.amount.abs_diff(c.expected_amount));
            if diff * 10_000 <= u128::from(c.tolerance_bps) * u128::from(c.expected_amount) {
                matching = true;
                break;
            }
        }
        let met = matching || total >= c.expected_amount;
        Ok(WitnessResult {
            condition_met: met,
            source: format!("{}-blockchain", c.network),
            confidence_bps: if met { 10_000 } else { 0 },
            timestamp: now,
        })
    }
    fn extract_outcome(&self, r: &WitnessResult) -> &'static str {
        if r.condition_met {
            "paid"
        } else {
            "unpaid"
        }
    }
    fn describe(&self) -> String {
        format!(
            "Payment of {} {} to {} on {}",
            self.cfg.expected_amount, self.cfg.asset, self.cfg.recipient, self.cfg.network
        )
    }
    fn witness_type(&self) -> WitnessType {
        WitnessType::Payment
    }
}

/// Price observation (price in fixed-point units chosen by the deployment).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriceData {
    /// Symbol.
    pub symbol: String,
    /// Price in fixed-point units.
    pub price: u64,
    /// Quote currency.
    pub currency: String,
    /// Observation time.
    pub timestamp: u64,
    /// Source label.
    pub source: String,
}

/// Price data source.
pub trait PriceClient {
    /// Latest price.
    fn price(&self, symbol: &str, currency: &str) -> Result<PriceData>;
}

/// Threshold direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// `price >= threshold`.
    Above,
    /// `price <= threshold`.
    Below,
}

/// Threshold witness configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdConfig {
    /// Symbol.
    pub symbol: String,
    /// Threshold in the same fixed-point units as the client's prices.
    pub threshold: u64,
    /// Direction.
    pub direction: Direction,
    /// Quote currency (legacy default "USD").
    pub currency: String,
    /// Maximum accepted age of the observation, seconds.
    pub max_age_secs: u64,
}

/// Threshold witness.
pub struct ThresholdWitness<P: PriceClient> {
    cfg: ThresholdConfig,
    client: P,
}

impl<P: PriceClient> ThresholdWitness<P> {
    /// Build.
    pub fn new(cfg: ThresholdConfig, client: P) -> Self {
        ThresholdWitness { cfg, client }
    }
}

impl<P: PriceClient> Witness for ThresholdWitness<P> {
    fn check(&self, now: u64) -> Result<WitnessResult> {
        let c = &self.cfg;
        let p = self.client.price(&c.symbol, &c.currency)?;
        if p.symbol != c.symbol || p.currency != c.currency {
            return Err(Error::Rejected("price data for a different pair"));
        }
        if p.timestamp > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
            return Err(Error::Rejected("price data from the future"));
        }
        if now.saturating_sub(p.timestamp) > c.max_age_secs {
            return Err(Error::Rejected("stale price data"));
        }
        let met = match c.direction {
            Direction::Above => p.price >= c.threshold,
            Direction::Below => p.price <= c.threshold,
        };
        Ok(WitnessResult {
            condition_met: met,
            source: p.source,
            confidence_bps: 10_000,
            timestamp: now,
        })
    }
    fn extract_outcome(&self, r: &WitnessResult) -> &'static str {
        if r.condition_met {
            "hit"
        } else {
            "miss"
        }
    }
    fn describe(&self) -> String {
        let d = match self.cfg.direction {
            Direction::Above => "above",
            Direction::Below => "below",
        };
        format!(
            "{} price {} {} {}",
            self.cfg.symbol, d, self.cfg.threshold, self.cfg.currency
        )
    }
    fn witness_type(&self) -> WitnessType {
        WitnessType::Threshold
    }
}

/// Time condition kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeKind {
    /// `now < target`.
    Before,
    /// `now >= target`.
    After,
    /// `|now - target| <= 60`.
    Exact,
}

/// Time witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeWitness {
    /// Target time (unix seconds).
    pub target_time: u64,
    /// Kind.
    pub kind: TimeKind,
}

impl Witness for TimeWitness {
    fn check(&self, now: u64) -> Result<WitnessResult> {
        let met = match self.kind {
            TimeKind::Before => now < self.target_time,
            TimeKind::After => now >= self.target_time,
            TimeKind::Exact => now.abs_diff(self.target_time) <= 60,
        };
        Ok(WitnessResult {
            condition_met: met,
            source: "system-clock".to_string(),
            confidence_bps: 10_000,
            timestamp: now,
        })
    }
    fn extract_outcome(&self, r: &WitnessResult) -> &'static str {
        if r.condition_met {
            "triggered"
        } else {
            "pending"
        }
    }
    fn describe(&self) -> String {
        let k = match self.kind {
            TimeKind::Before => "before",
            TimeKind::After => "after",
            TimeKind::Exact => "exact",
        };
        format!("Time {} {}", k, self.target_time)
    }
    fn witness_type(&self) -> WitnessType {
        WitnessType::Time
    }
}

/// Composite logic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Logic {
    /// All children.
    And,
    /// Any child.
    Or,
}

/// Composite witness.
pub struct CompositeWitness {
    children: Vec<Box<dyn Witness>>,
    logic: Logic,
}

impl CompositeWitness {
    /// Build; empty composites are rejected (legacy `every([])` was vacuously true).
    pub fn new(children: Vec<Box<dyn Witness>>, logic: Logic) -> Result<Self> {
        if children.is_empty() {
            return Err(Error::Rejected("composite witness needs children"));
        }
        if children.len() > MAX_CHILDREN {
            return Err(Error::TooLarge("composite children"));
        }
        Ok(CompositeWitness { children, logic })
    }
}

impl Witness for CompositeWitness {
    fn check(&self, now: u64) -> Result<WitnessResult> {
        let mut results = Vec::with_capacity(self.children.len());
        for c in &self.children {
            results.push(c.check(now)?);
        }
        let met = match self.logic {
            Logic::And => results.iter().all(|r| r.condition_met),
            Logic::Or => results.iter().any(|r| r.condition_met),
        };
        let sum: u64 = results.iter().map(|r| u64::from(r.confidence_bps)).sum();
        let avg = (sum / results.len() as u64) as u16;
        Ok(WitnessResult {
            condition_met: met,
            source: "composite".to_string(),
            confidence_bps: avg,
            timestamp: now,
        })
    }
    fn extract_outcome(&self, r: &WitnessResult) -> &'static str {
        if r.condition_met {
            "satisfied"
        } else {
            "unsatisfied"
        }
    }
    fn describe(&self) -> String {
        let sep = match self.logic {
            Logic::And => " AND ",
            Logic::Or => " OR ",
        };
        self.children
            .iter()
            .map(|c| c.describe())
            .collect::<Vec<_>>()
            .join(sep)
    }
    fn witness_type(&self) -> WitnessType {
        WitnessType::Composite
    }
}
