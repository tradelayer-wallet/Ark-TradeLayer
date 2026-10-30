use tl_ark_dlc::storage::{MemoryStore, Store, WitnessType};
use tl_ark_dlc::witness::*;
use tl_ark_dlc::{Error, Result};

struct Chain(Vec<Transfer>);
impl BlockchainClient for Chain {
    fn transfers(&self, _n: &str, _to: &str, _a: &str, _from: u64) -> Result<Vec<Transfer>> {
        Ok(self.0.clone())
    }
}

struct Prices(PriceData);
impl PriceClient for Prices {
    fn price(&self, _s: &str, _c: &str) -> Result<PriceData> {
        Ok(self.0.clone())
    }
}

fn transfer(amount: u64, hash: &str) -> Transfer {
    Transfer {
        from: "payer".into(),
        to: "recipient".into(),
        amount,
        tx_hash: hash.into(),
        block_number: 100,
        timestamp: 1,
    }
}

fn pay_cfg(expected: u64) -> PaymentConfig {
    PaymentConfig {
        network: "ethereum".into(),
        recipient: "recipient".into(),
        expected_amount: expected,
        asset: "USDC".into(),
        from_block: 50,
        tolerance_bps: 100,
    }
}

fn pay(expected: u64, ts: Vec<Transfer>) -> Result<bool> {
    let w = PaymentWitness::new(pay_cfg(expected), Chain(ts))?;
    Ok(w.check(1_000)?.condition_met)
}

#[test]
fn payment_exact_tolerance_and_partial_sums() {
    assert_eq!(pay(10_000, vec![transfer(10_000, "a")]), Ok(true));
    // 1% tolerance, inclusive
    assert_eq!(pay(10_000, vec![transfer(9_900, "a")]), Ok(true));
    assert_eq!(pay(10_000, vec![transfer(10_100, "a")]), Ok(true));
    assert_eq!(pay(10_000, vec![transfer(9_899, "a")]), Ok(false));
    // several smaller transfers add up to the expected amount
    assert_eq!(
        pay(
            10_000,
            vec![
                transfer(4_000, "a"),
                transfer(3_000, "b"),
                transfer(3_000, "c")
            ]
        ),
        Ok(true)
    );
    assert_eq!(pay(10_000, vec![]), Ok(false));
    let w = PaymentWitness::new(pay_cfg(1), Chain(vec![])).unwrap();
    let r = w.check(5).unwrap();
    assert_eq!(w.extract_outcome(&r), "unpaid");
    assert_eq!(r.confidence_bps, 0);
    assert!(w.describe().contains("USDC"));
}

#[test]
fn payment_repaired_fail_open_cases() {
    // legacy: expectedAmount = 0 made `totalReceived >= 0` true with no payment
    assert!(PaymentWitness::new(pay_cfg(0), Chain(vec![])).is_err());
    // legacy: duplicates from the client were summed twice
    assert_eq!(
        pay(10_000, vec![transfer(4_000, "a"), transfer(4_000, "a")]),
        Ok(false)
    );
    // legacy: transfers to someone else / before from_block were trusted
    let mut other = transfer(10_000, "a");
    other.to = "attacker".into();
    assert_eq!(pay(10_000, vec![other]), Ok(false));
    let mut old = transfer(10_000, "b");
    old.block_number = 49;
    assert_eq!(pay(10_000, vec![old]), Ok(false));
    // overflow is an error, not wraparound
    assert_eq!(
        pay(
            u64::MAX / 2,
            vec![transfer(u64::MAX - 10, "a"), transfer(20, "b")]
        ),
        Err(Error::Overflow)
    );
    // bounded work
    let many: Vec<_> = (0..=MAX_TRANSFERS)
        .map(|i| transfer(1, &i.to_string()))
        .collect();
    assert!(matches!(pay(10_000, many), Err(Error::TooLarge(_))));
    let mut cfg = pay_cfg(1);
    cfg.tolerance_bps = 10_001;
    assert!(PaymentWitness::new(cfg, Chain(vec![])).is_err());
}

fn price(p: u64, ts: u64) -> PriceData {
    PriceData {
        symbol: "BTC".into(),
        price: p,
        currency: "USD".into(),
        timestamp: ts,
        source: "feed".into(),
    }
}

fn thr(dir: Direction, threshold: u64, p: PriceData) -> Result<WitnessResult> {
    ThresholdWitness::new(
        ThresholdConfig {
            symbol: "BTC".into(),
            threshold,
            direction: dir,
            currency: "USD".into(),
            max_age_secs: 300,
        },
        Prices(p),
    )
    .check(10_000)
}

#[test]
fn threshold_directions_and_input_checks() {
    assert!(
        thr(Direction::Above, 100, price(100, 9_990))
            .unwrap()
            .condition_met
    );
    assert!(
        !thr(Direction::Above, 100, price(99, 9_990))
            .unwrap()
            .condition_met
    );
    assert!(
        thr(Direction::Below, 100, price(100, 9_990))
            .unwrap()
            .condition_met
    );
    assert!(
        !thr(Direction::Below, 100, price(101, 9_990))
            .unwrap()
            .condition_met
    );
    // legacy accepted data for another pair and stale data
    let mut wrong = price(100, 9_990);
    wrong.symbol = "ETH".into();
    assert!(thr(Direction::Above, 1, wrong).is_err());
    let mut wrong = price(100, 9_990);
    wrong.currency = "EUR".into();
    assert!(thr(Direction::Above, 1, wrong).is_err());
    assert!(thr(Direction::Above, 1, price(100, 9_699)).is_err());
    assert!(thr(Direction::Above, 1, price(100, 9_700)).is_ok());
    assert!(thr(Direction::Above, 1, price(100, 10_061)).is_err());
    assert!(thr(Direction::Above, 1, price(100, 10_060)).is_ok());
    let w = ThresholdWitness::new(
        ThresholdConfig {
            symbol: "BTC".into(),
            threshold: 5,
            direction: Direction::Above,
            currency: "USD".into(),
            max_age_secs: 1,
        },
        Prices(price(1, 1)),
    );
    assert_eq!(
        w.extract_outcome(&thr(Direction::Above, 100, price(100, 9_990)).unwrap()),
        "hit"
    );
    assert!(w.describe().contains("above"));
}

#[test]
fn time_witness_boundaries() {
    let before = TimeWitness {
        target_time: 100,
        kind: TimeKind::Before,
    };
    assert!(before.check(99).unwrap().condition_met);
    assert!(!before.check(100).unwrap().condition_met);
    let after = TimeWitness {
        target_time: 100,
        kind: TimeKind::After,
    };
    assert!(!after.check(99).unwrap().condition_met);
    assert!(after.check(100).unwrap().condition_met);
    let exact = TimeWitness {
        target_time: 100,
        kind: TimeKind::Exact,
    };
    assert!(exact.check(40).unwrap().condition_met);
    assert!(!exact.check(39).unwrap().condition_met);
    assert!(exact.check(160).unwrap().condition_met);
    assert!(!exact.check(161).unwrap().condition_met);
    assert!(exact.check(0).is_ok());
    assert_eq!(
        exact.extract_outcome(&exact.check(100).unwrap()),
        "triggered"
    );
    assert_eq!(exact.extract_outcome(&exact.check(0).unwrap()), "pending");
}

#[test]
fn composite_logic_and_empty_rejection() {
    // legacy: every([]) === true, so an empty AND composite was "satisfied"
    assert!(CompositeWitness::new(vec![], Logic::And).is_err());
    assert!(CompositeWitness::new(vec![], Logic::Or).is_err());
    let t = |k, at| -> Box<dyn Witness> {
        Box::new(TimeWitness {
            target_time: at,
            kind: k,
        })
    };
    let and = CompositeWitness::new(
        vec![t(TimeKind::After, 10), t(TimeKind::Before, 20)],
        Logic::And,
    )
    .unwrap();
    assert!(and.check(15).unwrap().condition_met);
    assert!(!and.check(25).unwrap().condition_met);
    let or = CompositeWitness::new(
        vec![t(TimeKind::After, 100), t(TimeKind::Before, 20)],
        Logic::Or,
    )
    .unwrap();
    assert!(or.check(5).unwrap().condition_met);
    assert!(!or.check(50).unwrap().condition_met);
    assert!(and.describe().contains(" AND "));
    assert_eq!(and.witness_type(), WitnessType::Composite);
    let r = and.check(15).unwrap();
    assert_eq!(and.extract_outcome(&r), "satisfied");
    assert_eq!(r.confidence_bps, 10_000);
    // a failing child fails the whole check (no silent skip)
    struct Failing;
    impl Witness for Failing {
        fn check(&self, _: u64) -> Result<WitnessResult> {
            Err(Error::Chain("down".into()))
        }
        fn extract_outcome(&self, _: &WitnessResult) -> &'static str {
            "x"
        }
        fn describe(&self) -> String {
            "f".into()
        }
        fn witness_type(&self) -> WitnessType {
            WitnessType::Payment
        }
    }
    let c =
        CompositeWitness::new(vec![t(TimeKind::After, 1), Box::new(Failing)], Logic::Or).unwrap();
    assert!(c.check(5).is_err());
    let too_many: Vec<Box<dyn Witness>> =
        (0..=MAX_CHILDREN).map(|_| t(TimeKind::After, 1)).collect();
    assert!(CompositeWitness::new(too_many, Logic::And).is_err());
}

#[test]
fn witness_log_is_stored_newest_first() {
    let mut st = MemoryStore::new();
    let w = TimeWitness {
        target_time: 1,
        kind: TimeKind::After,
    };
    for now in [10, 30, 20] {
        let r = w.check(now).unwrap();
        st.insert_witness_log(r.to_log("evt", w.witness_type(), "{}".into()))
            .unwrap();
    }
    let rows = st.witness_logs("evt").unwrap();
    assert_eq!(
        rows.iter().map(|r| r.checked_at).collect::<Vec<_>>(),
        vec![30, 20, 10]
    );
    assert!(st.witness_logs("other").unwrap().is_empty());
}
