use tl_ark_dlc::attestation::*;
use tl_ark_dlc::keys::{oracle_secret, SyntheticKeyProvider};
use tl_ark_dlc::storage::*;
use tl_ark_dlc::Error;

fn setup() -> (Oracle<MemoryStore>, WriterToken) {
    let kp = SyntheticKeyProvider::from_label("store").unwrap();
    let mut o = Oracle::new(MemoryStore::new(), oracle_secret(&kp, 1).unwrap(), "w1").unwrap();
    o.announce(
        "n",
        Descriptor::Numeric(NumericDescriptor {
            base: 2,
            num_digits: 4,
            unit: String::new(),
            precision: 0,
            signed: false,
        }),
        10,
    )
    .unwrap();
    let tok = o.store_mut().acquire_writer("test").unwrap();
    (o, tok)
}

fn nu(o: &Oracle<MemoryStore>, i: u32, d: u8) -> NonceUse {
    NonceUse {
        index: i,
        r: o.store().nonce("n", i).unwrap().unwrap().r,
        digest: [d; 32],
    }
}

#[test]
fn begin_use_is_all_or_nothing() {
    let (mut o, tok) = setup();
    let first = nu(&o, 1, 1);
    o.store_mut().begin_use(&tok, "n", &[first]).unwrap();
    // second batch contains one fresh and one used nonce: nothing changes
    let batch = [nu(&o, 0, 2), nu(&o, 1, 3), nu(&o, 2, 4)];
    assert!(matches!(
        o.store_mut().begin_use(&tok, "n", &batch),
        Err(Error::NonceReused { index: 1, .. })
    ));
    for i in [0, 2, 3] {
        assert_eq!(
            o.store().nonce("n", i).unwrap().unwrap().state,
            NonceState::Fresh
        );
    }
    assert_eq!(
        o.store().nonce("n", 1).unwrap().unwrap().state,
        NonceState::Used { digest: [1; 32] }
    );
}

#[test]
fn begin_use_validates_requests() {
    let (mut o, tok) = setup();
    // duplicate index within one request
    let dup = [nu(&o, 0, 1), nu(&o, 0, 2)];
    assert!(matches!(
        o.store_mut().begin_use(&tok, "n", &dup),
        Err(Error::NonceReused { .. })
    ));
    assert_eq!(
        o.store().nonce("n", 0).unwrap().unwrap().state,
        NonceState::Fresh
    );
    // wrong R for the index
    let mut bad = nu(&o, 0, 1);
    bad.r[0] ^= 1;
    assert_eq!(
        o.store_mut().begin_use(&tok, "n", &[bad]),
        Err(Error::RBindingMismatch { index: 0 })
    );
    // unknown nonce / event
    let mut unknown = nu(&o, 0, 1);
    unknown.index = 9;
    assert!(matches!(
        o.store_mut().begin_use(&tok, "n", &[unknown]),
        Err(Error::NotFound(_))
    ));
    let probe = nu(&o, 0, 1);
    assert!(matches!(
        o.store_mut().begin_use(&tok, "missing", &[probe]),
        Err(Error::NotFound(_))
    ));
    // an old token is rejected for every mutating call
    let (mut o2, _t) = setup();
    let stale = o2.store_mut().acquire_writer("a").unwrap();
    let _newer = o2.store_mut().acquire_writer("b").unwrap();
    let u = nu(&o2, 0, 1);
    assert_eq!(
        o2.store_mut().begin_use(&stale, "n", &[u]),
        Err(Error::StaleWriter)
    );
}

#[test]
fn attestation_is_recorded_once_per_event() {
    let (mut o, tok) = setup();
    let rec = AttestationRecord {
        attestation_id: "att:n".into(),
        event_id: "n".into(),
        oracle_pubkey: o.public_key(),
        outcomes: vec![],
        signatures: vec![],
        attestation_time: 1,
        verified: false,
    };
    o.store_mut().record_attestation(&tok, rec.clone()).unwrap();
    assert!(matches!(
        o.store_mut().record_attestation(&tok, rec.clone()),
        Err(Error::Duplicate(_))
    ));
    let mut other = rec.clone();
    other.attestation_id = "att:n2".into();
    assert!(matches!(
        o.store_mut().record_attestation(&tok, other),
        Err(Error::Duplicate("event already attested"))
    ));
    let mut orphan = rec;
    orphan.event_id = "ghost".into();
    orphan.attestation_id = "att:ghost".into();
    assert!(matches!(
        o.store_mut().record_attestation(&tok, orphan),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn many_events_exercise_both_nonce_parities() {
    let kp = SyntheticKeyProvider::from_label("parity").unwrap();
    let mut o = Oracle::new(MemoryStore::new(), oracle_secret(&kp, 1).unwrap(), "w").unwrap();
    for i in 0..40 {
        let id = format!("e{i}");
        let ann = o
            .announce(
                &id,
                Descriptor::Enum {
                    outcomes: vec!["a".into(), "b".into()],
                },
                5,
            )
            .unwrap();
        let att = o.attest_enum(&id, i % 2, 5).unwrap();
        verify_attestation(&ann, &att).unwrap();
    }
}
