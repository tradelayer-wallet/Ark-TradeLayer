use tl_ark_dlc::attestation::*;
use tl_ark_dlc::keys::{oracle_secret, SyntheticKeyProvider};
use tl_ark_dlc::loan::*;
use tl_ark_dlc::storage::{ContractType, LoanRecord, MemoryStore, Store};
use tl_ark_dlc::Error;

const T: u64 = 1_893_456_000;

struct Fixture {
    oracle: Oracle<MemoryStore>,
    repay_ann: Announcement,
    price_ann: Announcement,
}

fn fixture(label: &str) -> Fixture {
    let kp = SyntheticKeyProvider::from_label(label).unwrap();
    let mut oracle = Oracle::new(MemoryStore::new(), oracle_secret(&kp, 1).unwrap(), "w").unwrap();
    let repay_ann = oracle
        .announce(
            "repay-1",
            Descriptor::Binary {
                outcomes: ["paid".into(), "unpaid".into()],
            },
            T,
        )
        .unwrap();
    let price_ann = oracle
        .announce(
            "price-1",
            Descriptor::Binary {
                outcomes: ["hit".into(), "miss".into()],
            },
            T,
        )
        .unwrap();
    Fixture {
        oracle,
        repay_ann,
        price_ann,
    }
}

fn terms(oracle: [u8; 32]) -> CollateralizedTerms {
    CollateralizedTerms {
        loan_id: "loan-1".into(),
        lender: [1; 32],
        borrower: [2; 32],
        server: [3; 32],
        oracle,
        terms_hash: [4; 32],
        repayment_event_id: "repay-1".into(),
        price_event_id: "price-1".into(),
        principal: 300_000,
        collateral: 1_000_000,
        maturity: T,
        grace_period: 86_400,
        exit_delay: 1008,
    }
}

fn funded(f: &Fixture) -> Loan {
    let mut l = Loan::new(terms(f.oracle.public_key()), 10_000).unwrap();
    l.fund(Funding {
        txid: [9; 32],
        vout: 0,
    })
    .unwrap();
    assert_eq!(l.status(), LoanStatus::Active);
    l
}

fn proof(f: &mut Fixture, event: &str, ann_is_repay: bool, outcome: bool) -> VerifiedOutcome {
    let att = f.oracle.attest_binary(event, outcome, T).unwrap();
    let ann = if ann_is_repay { &f.repay_ann } else { &f.price_ann };
    verify_attestation(ann, &att).unwrap()
}

#[test]
fn borrow_fund_repay_full() {
    let mut f = fixture("l1");
    let mut l = funded(&f);
    let p = proof(&mut f, "repay-1", true, true);
    let s = l.repay_full(&p).unwrap();
    assert_eq!(
        s,
        Split {
            borrower: 1_000_000,
            lender: 0
        }
    );
    assert_eq!(l.status(), LoanStatus::Repaid);
    assert_eq!(l.settlement(), Some(s));
    // terminal: nothing more is possible
    assert!(matches!(l.claim_default(T + 10_000_000), Err(Error::IllegalTransition { .. })));
    assert!(matches!(l.emergency_exit(5000), Err(Error::IllegalTransition { .. })));
    assert!(matches!(l.repay_full(&p), Err(Error::IllegalTransition { .. })));
}

#[test]
fn repay_partial_splits_sum_to_collateral() {
    let mut f = fixture("l2");
    let mut l = funded(&f);
    let p = proof(&mut f, "repay-1", true, true);
    assert!(l.repay_partial(&p, 0).is_err());
    assert!(l.repay_partial(&p, 300_000).is_err());
    let s = l.repay_partial(&p, 100_000).unwrap();
    assert_eq!((s.borrower, s.lender), (333_333, 666_667));
    assert_eq!(s.total().unwrap(), 1_000_000);
}

#[test]
fn proofs_are_bound_to_event_outcome_and_oracle() {
    let mut f = fixture("l3");
    let mut l = funded(&f);
    // right oracle, but a price-event "hit" cannot repay and a repay "paid" cannot liquidate
    let hit = proof(&mut f, "price-1", false, true);
    assert!(l.repay_full(&hit).is_err());
    let mut l2 = funded(&f);
    let paid = proof(&mut f, "repay-1", true, true);
    assert!(l2.liquidate(&paid).is_err());
    assert!(l2.liquidate(&hit).is_ok());
    assert_eq!(l2.status(), LoanStatus::Liquidated);
    assert_eq!(l2.settlement().unwrap().lender, 1_000_000);

    // "unpaid" is a genuine attestation but not the required outcome
    let mut g = fixture("l3b");
    let mut l3 = funded(&g);
    let unpaid = proof(&mut g, "repay-1", true, false);
    assert!(l3.repay_full(&unpaid).is_err());
    assert_eq!(l3.status(), LoanStatus::Active);

    // a different oracle's attestation for an identically named event is rejected
    let mut h = fixture("other-oracle");
    let foreign = proof(&mut h, "repay-1", true, true);
    let mut l4 = funded(&f);
    assert!(l4.repay_full(&foreign).is_err());
}

#[test]
fn default_and_emergency_boundaries() {
    let f = fixture("l4");
    let mut l = funded(&f);
    assert!(l.claim_default(T + 86_399).is_err());
    let s = l.claim_default(T + 86_400).unwrap();
    assert_eq!(s.lender, 1_000_000);
    assert_eq!(l.status(), LoanStatus::Defaulted);

    let mut e = funded(&f);
    assert!(e.emergency_exit(1007).is_err());
    let s = e.emergency_exit(1008).unwrap();
    // UNRESOLVED QUESTION pinned by this test: the borrower leaves with 90%
    assert_eq!((s.borrower, s.lender), (900_000, 100_000));
    assert_eq!(e.status(), LoanStatus::EmergencyExited);
}

#[test]
fn illegal_transitions_and_funding() {
    let f = fixture("l5");
    let mut l = Loan::new(terms(f.oracle.public_key()), 10_000).unwrap();
    assert_eq!(l.status(), LoanStatus::Pending);
    assert!(matches!(l.claim_default(T * 2), Err(Error::IllegalTransition { .. })));
    assert!(matches!(l.emergency_exit(9999), Err(Error::IllegalTransition { .. })));
    assert!(l.open_dispute().is_err());
    l.fund(Funding {
        txid: [1; 32],
        vout: 1,
    })
    .unwrap();
    assert!(matches!(
        l.fund(Funding {
            txid: [1; 32],
            vout: 1
        }),
        Err(Error::Duplicate(_))
    ));
}

#[test]
fn dispute_path() {
    let f = fixture("l6");
    let mut l = funded(&f);
    assert!(l.resolve_for_lender().is_err());
    l.open_dispute().unwrap();
    assert_eq!(l.status(), LoanStatus::Disputed);
    assert!(l.open_dispute().is_err());
    let s = l.resolve_for_borrower().unwrap();
    assert_eq!(s.borrower, 1_000_000);
    assert_eq!(l.status(), LoanStatus::Repaid);
}

#[test]
fn terms_are_validated() {
    let o = [5u8; 32];
    let mut t = terms(o);
    t.principal = 0;
    assert!(Loan::new(t, 10_000).is_err());
    let mut t = terms(o);
    t.collateral = 9_999;
    assert!(Loan::new(t, 10_000).is_err());
    let mut t = terms(o);
    t.borrower = t.lender;
    assert!(Loan::new(t, 10_000).is_err());
    let mut t = terms(o);
    t.price_event_id = t.repayment_event_id.clone();
    assert!(Loan::new(t, 10_000).is_err());
    let mut t = terms(o);
    t.grace_period = u64::MAX;
    assert_eq!(Loan::new(t, 10_000), Err(Error::Overflow));
    let mut t = terms(o);
    t.exit_delay = 0;
    assert!(Loan::new(t, 10_000).is_err());
    let mut t = terms(o);
    t.loan_id = "bad id".into();
    assert!(Loan::new(t, 10_000).is_err());
}

#[test]
fn accounting_never_leaks_value() {
    // deterministic sweep, including values near u64::MAX
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..20_000 {
        let c = next() >> (next() % 64);
        let p = (next() >> (next() % 64)).max(2);
        let r = 1 + next() % (p - 1);
        let s = split_repay_partial(c, p, r).unwrap();
        assert_eq!(s.total().unwrap(), c);
        assert_eq!(split_emergency(c).total().unwrap(), c);
        assert_eq!(split_to_lender(c).total().unwrap(), c);
        assert_eq!(split_repay_full(c).total().unwrap(), c);
        assert!(split_emergency(c).lender <= c / 10);
    }
}

#[test]
fn store_cas_follows_the_edges() {
    let mut st = MemoryStore::new();
    let rec = LoanRecord {
        loan_id: "loan-1".into(),
        contract_type: ContractType::Collateralized,
        lender_pubkey: [1; 32],
        borrower_pubkey: [2; 32],
        server_pubkey: [3; 32],
        oracle_pubkey: [4; 32],
        terms_hash: [5; 32],
        principal_amount: 1,
        collateral_amount: Some(2),
        interest_amount: 0,
        maturity_time: T,
        repayment_deadline: T,
        repayment_event_id: None,
        price_event_id: None,
        other_event_ids: vec![],
        funding: None,
        locking_script: vec![0x51],
        exit_delay: 1008,
        status: LoanStatus::Pending,
        settlement_txid: None,
        settlement_outcome: None,
    };
    st.insert_loan(rec.clone()).unwrap();
    assert!(matches!(st.insert_loan(rec), Err(Error::Duplicate(_))));
    assert!(matches!(
        st.cas_loan_status("loan-1", LoanStatus::Pending, LoanStatus::Repaid),
        Err(Error::IllegalTransition { .. })
    ));
    st.cas_loan_status("loan-1", LoanStatus::Pending, LoanStatus::Active)
        .unwrap();
    // stale expectation
    assert!(st
        .cas_loan_status("loan-1", LoanStatus::Pending, LoanStatus::Active)
        .is_err());
    st.cas_loan_status("loan-1", LoanStatus::Active, LoanStatus::Liquidated)
        .unwrap();
    assert_eq!(st.get_loan("loan-1").unwrap().unwrap().status, LoanStatus::Liquidated);
    assert!(st
        .cas_loan_status("missing", LoanStatus::Pending, LoanStatus::Active)
        .is_err());
}
