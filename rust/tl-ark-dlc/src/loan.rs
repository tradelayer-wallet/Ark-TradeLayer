//! Collateralized VTXO loan lifecycle and value accounting.
//!
//! Source: `vtxo-loan-system/contracts/CollateralizedLoan.ark` (paths `repayFull`, `repayPartial`,
//! `liquidate`, `claimDefault`, `emergencyExit`) and the `LoanContract` status enum in
//! `src/storage/schemas.ts`. The Ark script semantics (signatures, output scripts) are NOT ported;
//! this module ports the state machine and the arithmetic that decides who receives how much.
//!
//! Every settlement returns a [`Split`] whose parts always sum to the collateral (checked in
//! tests and proved in `lean/TlArkDlc/Loan.lean`).

use crate::attestation::VerifiedOutcome;
use crate::error::{Error, Result};
use crate::util::check_ident;

/// Fixed-point scale of the repayment ratio in `repayPartial` (`* 1000000`).
pub const RATIO_SCALE: u64 = 1_000_000;
/// `emergencyExit` penalty is `collateral / EMERGENCY_PENALTY_DIVISOR` (10%), floor division.
///
/// UNRESOLVED QUESTION (kept as the legacy contract): after the exit delay the borrower may
/// leave with 90% of the collateral regardless of any outstanding principal, and without any
/// check that the server is actually unavailable.
pub const EMERGENCY_PENALTY_DIVISOR: u64 = 10;

/// Loan status. The first six are the legacy schema enum; `EmergencyExited` is added because the
/// legacy enum has no state for the `emergencyExit` path (versioned protocol change).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoanStatus {
    /// Created, not funded.
    Pending,
    /// Funded VTXO.
    Active,
    /// Repaid (fully or partially, terminal).
    Repaid,
    /// Defaulted (terminal).
    Defaulted,
    /// Liquidated (terminal).
    Liquidated,
    /// Under dispute (non-terminal).
    Disputed,
    /// Borrower used the unilateral emergency exit (terminal).
    EmergencyExited,
}

impl LoanStatus {
    /// Stable name.
    pub fn name(self) -> &'static str {
        match self {
            LoanStatus::Pending => "pending",
            LoanStatus::Active => "active",
            LoanStatus::Repaid => "repaid",
            LoanStatus::Defaulted => "defaulted",
            LoanStatus::Liquidated => "liquidated",
            LoanStatus::Disputed => "disputed",
            LoanStatus::EmergencyExited => "emergency_exited",
        }
    }

    /// True if no transition leaves this state.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            LoanStatus::Repaid
                | LoanStatus::Defaulted
                | LoanStatus::Liquidated
                | LoanStatus::EmergencyExited
        )
    }

    /// The allowed-edge relation (mirrored by `allowed` in `lean/TlArkDlc/Loan.lean`).
    pub fn can_transition_to(self, to: LoanStatus) -> bool {
        use LoanStatus::*;
        matches!(
            (self, to),
            (Pending, Active)
                | (Active, Repaid)
                | (Active, Defaulted)
                | (Active, Liquidated)
                | (Active, Disputed)
                | (Active, EmergencyExited)
                | (Disputed, Repaid)
                | (Disputed, Defaulted)
                | (Disputed, Liquidated)
                | (Disputed, EmergencyExited)
        )
    }
}

/// Division of the collateral. Parts are unsigned, so no share is ever negative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Split {
    /// Satoshis to the borrower.
    pub borrower: u64,
    /// Satoshis to the lender.
    pub lender: u64,
}

impl Split {
    /// Sum of both shares (checked).
    pub fn total(&self) -> Result<u64> {
        self.borrower
            .checked_add(self.lender)
            .ok_or(Error::Overflow)
    }
}

/// `repayFull`: the borrower gets everything back.
pub fn split_repay_full(collateral: u64) -> Split {
    Split {
        borrower: collateral,
        lender: 0,
    }
}

/// `repayPartial`: `ratio = repaid*1e6/principal`, `lender = collateral*(1e6-ratio)/1e6`,
/// `borrower = collateral - lender` (floor divisions, as in the contract).
pub fn split_repay_partial(collateral: u64, principal: u64, repaid: u64) -> Result<Split> {
    if principal == 0 || repaid == 0 || repaid >= principal {
        return Err(Error::Rejected(
            "partial repayment must be in (0, principal)",
        ));
    }
    let ratio = (u128::from(repaid) * u128::from(RATIO_SCALE)) / u128::from(principal);
    // ratio < RATIO_SCALE because repaid < principal
    let lender128 =
        (u128::from(collateral) * (u128::from(RATIO_SCALE) - ratio)) / u128::from(RATIO_SCALE);
    let lender = u64::try_from(lender128).map_err(|_| Error::Overflow)?;
    let borrower = collateral.checked_sub(lender).ok_or(Error::Overflow)?;
    Ok(Split { borrower, lender })
}

/// `liquidate` / `claimDefault`: all collateral to the lender.
pub fn split_to_lender(collateral: u64) -> Split {
    Split {
        borrower: 0,
        lender: collateral,
    }
}

/// `emergencyExit`: `penalty = collateral/10` to the lender, the rest (90%) to the borrower.
pub fn split_emergency(collateral: u64) -> Split {
    let penalty = collateral / EMERGENCY_PENALTY_DIVISOR;
    Split {
        borrower: collateral - penalty,
        lender: penalty,
    }
}

/// Immutable terms of a collateralized loan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralizedTerms {
    /// Unique loan id.
    pub loan_id: String,
    /// Lender key (x-only).
    pub lender: [u8; 32],
    /// Borrower key (x-only).
    pub borrower: [u8; 32],
    /// ASP key (x-only).
    pub server: [u8; 32],
    /// Oracle key (x-only).
    pub oracle: [u8; 32],
    /// Hash of the off-chain loan terms.
    pub terms_hash: [u8; 32],
    /// Oracle event id for repayment ("paid").
    pub repayment_event_id: String,
    /// Oracle event id for the liquidation price trigger ("hit").
    pub price_event_id: String,
    /// Principal in satoshis.
    pub principal: u64,
    /// Collateral in satoshis.
    pub collateral: u64,
    /// Maturity (unix seconds).
    pub maturity: u64,
    /// Grace period after maturity (seconds).
    pub grace_period: u64,
    /// Exit delay in blocks (`exit = 1008` in the contract).
    pub exit_delay: u32,
}

impl CollateralizedTerms {
    /// Structural validation (fail closed).
    pub fn validate(&self, min_contract_value: u64) -> Result<()> {
        check_ident(&self.loan_id, 64, "loan id")?;
        check_ident(&self.repayment_event_id, 128, "repayment event id")?;
        check_ident(&self.price_event_id, 128, "price event id")?;
        if self.repayment_event_id == self.price_event_id {
            return Err(Error::Rejected("repayment and price events must differ"));
        }
        if self.principal == 0 || self.collateral == 0 {
            return Err(Error::Rejected("principal and collateral must be positive"));
        }
        if self.collateral < min_contract_value {
            return Err(Error::Rejected("collateral below minimum contract value"));
        }
        if self.lender == self.borrower {
            return Err(Error::Rejected("lender and borrower must differ"));
        }
        if self.maturity == 0 || self.exit_delay == 0 || self.exit_delay > 65_535 {
            return Err(Error::Rejected("bad maturity or exit delay"));
        }
        self.maturity
            .checked_add(self.grace_period)
            .ok_or(Error::Overflow)?;
        Ok(())
    }

    fn default_time(&self) -> Result<u64> {
        self.maturity
            .checked_add(self.grace_period)
            .ok_or(Error::Overflow)
    }
}

/// Funding outpoint of the loan VTXO.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Funding {
    /// Funding txid (internal byte order as supplied).
    pub txid: [u8; 32],
    /// Output index.
    pub vout: u32,
}

/// A collateralized loan and its status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loan {
    terms: CollateralizedTerms,
    status: LoanStatus,
    funding: Option<Funding>,
    settled: Option<Split>,
}

impl Loan {
    /// Borrow: create a pending loan from validated terms.
    pub fn new(terms: CollateralizedTerms, min_contract_value: u64) -> Result<Loan> {
        terms.validate(min_contract_value)?;
        Ok(Loan {
            terms,
            status: LoanStatus::Pending,
            funding: None,
            settled: None,
        })
    }

    /// Terms.
    pub fn terms(&self) -> &CollateralizedTerms {
        &self.terms
    }

    /// Current status.
    pub fn status(&self) -> LoanStatus {
        self.status
    }

    /// Final division of the collateral, once settled.
    pub fn settlement(&self) -> Option<Split> {
        self.settled
    }

    fn go(&mut self, to: LoanStatus) -> Result<()> {
        if !self.status.can_transition_to(to) {
            return Err(Error::IllegalTransition {
                from: self.status.name(),
                to: to.name(),
            });
        }
        self.status = to;
        Ok(())
    }

    fn settle(&mut self, to: LoanStatus, split: Split) -> Result<Split> {
        if split.total()? != self.terms.collateral {
            // Defensive: unreachable by construction, but never settle an unbalanced split.
            return Err(Error::Rejected("split does not sum to collateral"));
        }
        self.go(to)?;
        self.settled = Some(split);
        Ok(split)
    }

    /// `Pending -> Active` once the VTXO is funded.
    pub fn fund(&mut self, funding: Funding) -> Result<()> {
        if self.funding.is_some() {
            return Err(Error::Duplicate("loan already funded"));
        }
        self.go(LoanStatus::Active)?;
        self.funding = Some(funding);
        Ok(())
    }

    fn check_proof(&self, proof: &VerifiedOutcome, event: &str, outcome: &str) -> Result<()> {
        if proof.oracle_pubkey() != &self.terms.oracle {
            return Err(Error::Rejected("attestation by a different oracle"));
        }
        if proof.event_id() != event {
            return Err(Error::Rejected("attestation for a different event"));
        }
        if proof.outcome() != Some(outcome) {
            return Err(Error::Rejected("attested outcome is not the required one"));
        }
        Ok(())
    }

    /// `repayFull`: requires an attestation `paid` for the repayment event.
    pub fn repay_full(&mut self, proof: &VerifiedOutcome) -> Result<Split> {
        self.check_proof(proof, &self.terms.repayment_event_id.clone(), "paid")?;
        let s = split_repay_full(self.terms.collateral);
        self.settle(LoanStatus::Repaid, s)
    }

    /// `repayPartial`: attestation `paid` plus a repaid amount in `(0, principal)`.
    pub fn repay_partial(&mut self, proof: &VerifiedOutcome, repaid: u64) -> Result<Split> {
        self.check_proof(proof, &self.terms.repayment_event_id.clone(), "paid")?;
        let s = split_repay_partial(self.terms.collateral, self.terms.principal, repaid)?;
        self.settle(LoanStatus::Repaid, s)
    }

    /// `liquidate`: requires an attestation `hit` for the price event.
    pub fn liquidate(&mut self, proof: &VerifiedOutcome) -> Result<Split> {
        self.check_proof(proof, &self.terms.price_event_id.clone(), "hit")?;
        self.settle(
            LoanStatus::Liquidated,
            split_to_lender(self.terms.collateral),
        )
    }

    /// `claimDefault`: allowed once `now >= maturity + grace_period`.
    pub fn claim_default(&mut self, now: u64) -> Result<Split> {
        if now < self.terms.default_time()? {
            return Err(Error::Rejected("grace period not expired"));
        }
        self.settle(
            LoanStatus::Defaulted,
            split_to_lender(self.terms.collateral),
        )
    }

    /// `emergencyExit`: allowed once the VTXO is `exit_delay` blocks old.
    pub fn emergency_exit(&mut self, vtxo_age_blocks: u32) -> Result<Split> {
        if vtxo_age_blocks < self.terms.exit_delay {
            return Err(Error::Rejected("exit timelock not satisfied"));
        }
        self.settle(
            LoanStatus::EmergencyExited,
            split_emergency(self.terms.collateral),
        )
    }

    /// `Active -> Disputed`.
    pub fn open_dispute(&mut self) -> Result<()> {
        self.go(LoanStatus::Disputed)
    }

    /// Resolve a dispute in favour of the borrower (`Repaid`, full collateral back).
    pub fn resolve_for_borrower(&mut self) -> Result<Split> {
        if self.status != LoanStatus::Disputed {
            return Err(Error::Rejected("not disputed"));
        }
        self.settle(LoanStatus::Repaid, split_repay_full(self.terms.collateral))
    }

    /// Resolve a dispute in favour of the lender (`Defaulted`, full collateral to the lender).
    pub fn resolve_for_lender(&mut self) -> Result<Split> {
        if self.status != LoanStatus::Disputed {
            return Err(Error::Rejected("not disputed"));
        }
        self.settle(
            LoanStatus::Defaulted,
            split_to_lender(self.terms.collateral),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_split_matches_contract_arithmetic() {
        // collateral 1_000_000, principal 300_000, repaid 100_000 -> ratio 333_333
        let s = split_repay_partial(1_000_000, 300_000, 100_000).unwrap();
        assert_eq!(s.lender, 1_000_000 * (1_000_000 - 333_333) / 1_000_000);
        assert_eq!(s.lender, 666_667);
        assert_eq!(s.borrower, 333_333);
        assert_eq!(s.total().unwrap(), 1_000_000);
    }

    #[test]
    fn partial_split_bounds() {
        assert!(split_repay_partial(10, 100, 0).is_err());
        assert!(split_repay_partial(10, 100, 100).is_err());
        assert!(split_repay_partial(10, 100, 101).is_err());
        assert!(split_repay_partial(10, 0, 1).is_err());
        let s = split_repay_partial(u64::MAX, u64::MAX, u64::MAX - 1).unwrap();
        assert_eq!(s.total().unwrap(), u64::MAX);
    }

    #[test]
    fn emergency_is_ninety_ten_floor() {
        let s = split_emergency(1_000_005);
        assert_eq!(s.lender, 100_000);
        assert_eq!(s.borrower, 900_005);
        assert_eq!(split_emergency(9).lender, 0);
        assert_eq!(split_emergency(9).borrower, 9);
    }

    #[test]
    fn edges() {
        use LoanStatus::*;
        for t in [Repaid, Defaulted, Liquidated, EmergencyExited] {
            for to in [
                Pending,
                Active,
                Repaid,
                Defaulted,
                Liquidated,
                Disputed,
                EmergencyExited,
            ] {
                assert!(!t.can_transition_to(to));
            }
        }
        assert!(Pending.can_transition_to(Active));
        assert!(!Pending.can_transition_to(Repaid));
        assert!(!Active.can_transition_to(Pending));
    }
}
