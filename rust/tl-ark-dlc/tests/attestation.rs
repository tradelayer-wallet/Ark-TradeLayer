use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
use tl_ark_dlc::attestation::*;
use tl_ark_dlc::keys::{oracle_secret, SyntheticKeyProvider};
use tl_ark_dlc::legacy;
use tl_ark_dlc::storage::{EventAnnouncementRecord, MemoryStore, NonceState, Store};
use tl_ark_dlc::Error;

const MATURITY: u64 = 1_893_456_000;

fn oracle(label: &str) -> Oracle<MemoryStore> {
    let kp = SyntheticKeyProvider::from_label(label).unwrap();
    let sk = oracle_secret(&kp, 1).unwrap();
    Oracle::new(MemoryStore::new(), sk, "writer-1").unwrap()
}

fn enum_desc() -> Descriptor {
    Descriptor::Enum {
        outcomes: vec!["fulfilled".into(), "defaulted".into(), "expired".into()],
    }
}

fn numeric_desc(signed: bool) -> Descriptor {
    Descriptor::Numeric(NumericDescriptor {
        base: 2,
        num_digits: 8,
        unit: "USD".into(),
        precision: 0,
        signed,
    })
}

#[test]
fn enum_roundtrip_and_independent_library_verification() {
    let mut o = oracle("rt");
    let ann = o.announce("evt-1", enum_desc(), MATURITY).unwrap();
    ann.verify().unwrap();
    let att = o.attest_enum("evt-1", 1, MATURITY).unwrap();
    assert_eq!(att.outcomes, vec!["defaulted".to_string()]);
    assert_eq!(att.signatures[0][..32], ann.nonce_points[0][..]);
    let v = verify_attestation(&ann, &att).unwrap();
    assert_eq!(v.outcome(), Some("defaulted"));
    assert_eq!(v.event_id(), "evt-1");

    // direct library check of the BIP-340 signature over the documented digest
    let digest = attestation_digest(
        &ann.oracle_pubkey,
        "evt-1",
        &ann.digest().unwrap(),
        0,
        &ann.nonce_points[0],
        "defaulted",
    )
    .unwrap();
    let secp = Secp256k1::verification_only();
    let sig = schnorr::Signature::from_slice(&att.signatures[0]).unwrap();
    let pk = XOnlyPublicKey::from_slice(&ann.oracle_pubkey).unwrap();
    secp.verify_schnorr(&sig, &Message::from_digest(digest), &pk)
        .unwrap();

    let rec = o
        .store()
        .get_attestation(&attestation_id("evt-1"))
        .unwrap()
        .unwrap();
    assert!(rec.verified);
    assert_eq!(rec.signatures, att.signatures);
    assert_eq!(
        o.store()
            .get_announcement("evt-1")
            .unwrap()
            .unwrap()
            .attestation_id,
        Some(attestation_id("evt-1"))
    );
}

#[test]
fn numeric_and_binary_roundtrip() {
    let mut o = oracle("num");
    let ann = o.announce("price", numeric_desc(true), MATURITY).unwrap();
    assert_eq!(ann.nonce_points.len(), 9);
    let att = o.attest_numeric("price", -37, MATURITY + 5).unwrap();
    assert_eq!(att.outcomes.len(), 9);
    assert_eq!(att.outcomes[0], "-");
    verify_attestation(&ann, &att).unwrap();

    let bann = o
        .announce(
            "paid",
            Descriptor::Binary {
                outcomes: ["paid".into(), "unpaid".into()],
            },
            MATURITY,
        )
        .unwrap();
    let batt = o.attest_binary("paid", true, MATURITY).unwrap();
    let v = verify_attestation(&bann, &batt).unwrap();
    assert_eq!(v.outcome(), Some("paid"));
}

#[test]
fn refuses_before_maturity_and_bad_outcomes() {
    let mut o = oracle("bad");
    o.announce("e", enum_desc(), MATURITY).unwrap();
    assert_eq!(o.attest_enum("e", 0, MATURITY - 1), Err(Error::NotMatured));
    assert!(o.attest("e", vec!["nope".into()], MATURITY).is_err());
    assert!(o.attest("e", vec![], MATURITY).is_err());
    assert!(o
        .attest("e", vec!["fulfilled".into(), "expired".into()], MATURITY)
        .is_err());
    assert!(o.attest_enum("e", 9, MATURITY).is_err());
    // none of the refusals consumed the nonce
    assert_eq!(
        o.store().nonce("e", 0).unwrap().unwrap().state,
        NonceState::Fresh
    );
    o.attest_enum("e", 0, MATURITY).unwrap();

    o.announce("u", numeric_desc(false), MATURITY).unwrap();
    assert!(o.attest_numeric("u", -1, MATURITY).is_err());
    assert!(o.attest_numeric("u", 256, MATURITY).is_err());
    assert!(o.attest_numeric("nonexistent", 1, MATURITY).is_err());
    assert!(o.attest_enum("u", 0, MATURITY).is_err());
}

#[test]
fn nonce_is_single_use() {
    let mut o = oracle("reuse");
    o.announce("e", enum_desc(), MATURITY).unwrap();
    o.attest_enum("e", 0, MATURITY).unwrap();
    // a different outcome with the same nonce would leak the key: refused
    let e = o.attest_enum("e", 1, MATURITY).unwrap_err();
    assert!(matches!(e, Error::NonceReused { .. }), "{e:?}");
    // even the same outcome is refused (one attestation per event)
    assert!(o.attest_enum("e", 0, MATURITY).is_err());
    // the store refuses a direct second begin_use as well
    let tok = o.store_mut().acquire_writer("x").unwrap();
    let nu = tl_ark_dlc::storage::NonceUse {
        index: 0,
        r: o.store().nonce("e", 0).unwrap().unwrap().r,
        digest: [7; 32],
    };
    assert!(matches!(
        o.store_mut().begin_use(&tok, "e", &[nu]),
        Err(Error::NonceReused { .. })
    ));
}

#[test]
fn nonce_use_is_all_or_nothing_for_numeric_events() {
    let mut o = oracle("aon");
    o.announce("n", numeric_desc(false), MATURITY).unwrap();
    // burn nonce 3 by hand
    let tok = o.store_mut().acquire_writer("w2").unwrap();
    let r3 = o.store().nonce("n", 3).unwrap().unwrap().r;
    o.store_mut()
        .begin_use(
            &tok,
            "n",
            &[tl_ark_dlc::storage::NonceUse {
                index: 3,
                r: r3,
                digest: [1; 32],
            }],
        )
        .unwrap();
    // the oracle's own token is now stale (single writer), so it cannot sign at all
    assert_eq!(o.attest_numeric("n", 5, MATURITY), Err(Error::StaleWriter));
}

#[test]
fn persist_before_sign() {
    let mut o = oracle("pbs");
    o.announce("e", enum_desc(), MATURITY).unwrap();

    // 1. persistence of the nonce use fails: nothing is signed, nonce stays fresh, retry works
    o.store_mut().fail_begin_use = true;
    assert!(matches!(
        o.attest_enum("e", 0, MATURITY),
        Err(Error::Storage(_))
    ));
    assert_eq!(
        o.store().nonce("e", 0).unwrap().unwrap().state,
        NonceState::Fresh
    );
    o.store_mut().fail_begin_use = false;

    // 2. the nonce use persisted but recording the attestation fails: nonce is burned for good
    o.store_mut().fail_record_attestation = true;
    assert!(matches!(
        o.attest_enum("e", 0, MATURITY),
        Err(Error::Storage(_))
    ));
    assert!(matches!(
        o.store().nonce("e", 0).unwrap().unwrap().state,
        NonceState::Used { .. }
    ));
    o.store_mut().fail_record_attestation = false;
    for i in 0..3 {
        assert!(
            matches!(
                o.attest_enum("e", i, MATURITY),
                Err(Error::NonceReused { .. })
            ),
            "retry {i} must be refused"
        );
    }
}

#[test]
fn single_writer_fencing() {
    let mut o = oracle("fence");
    o.announce("a", enum_desc(), MATURITY).unwrap();
    // a second process takes over the store
    let _newer = o.store_mut().acquire_writer("process-2").unwrap();
    assert_eq!(o.store().writer_owner(), Some("process-2"));
    assert_eq!(
        o.announce("b", enum_desc(), MATURITY),
        Err(Error::StaleWriter)
    );
    assert_eq!(o.attest_enum("a", 0, MATURITY), Err(Error::StaleWriter));
}

#[test]
fn r_binding_rejects_signature_with_other_r() {
    let mut o = oracle("rb");
    let a1 = o.announce("evt-a", enum_desc(), MATURITY).unwrap();
    let a2 = o.announce("evt-b", enum_desc(), MATURITY).unwrap();
    assert_ne!(a1.nonce_points, a2.nonce_points);
    let att1 = o.attest_enum("evt-a", 0, MATURITY).unwrap();

    // relabel event A's attestation as event B's: same oracle, same outcome, valid signature,
    // wrong R for B -> rejected by the R-binding check
    let mut moved = att1.clone();
    moved.event_id = "evt-b".into();
    assert_eq!(
        verify_attestation(&a2, &moved),
        Err(Error::RBindingMismatch { index: 0 })
    );
    // and by event id when not relabelled
    assert!(verify_attestation(&a2, &att1).is_err());

    // a signature whose R was swapped but is otherwise internally valid fails R binding first
    let mut forged = att1.clone();
    forged.signatures[0][..32].copy_from_slice(&a2.nonce_points[0]);
    assert_eq!(
        verify_attestation(&a1, &forged),
        Err(Error::RBindingMismatch { index: 0 })
    );
    // flipping an s byte keeps R but breaks the signature
    let mut bad = att1.clone();
    bad.signatures[0][63] ^= 1;
    assert_eq!(verify_attestation(&a1, &bad), Err(Error::SignatureInvalid));
    assert!(r_binding_ok(&a1.nonce_points[0], &att1.signatures[0]));
    assert!(!r_binding_ok(&a2.nonce_points[0], &att1.signatures[0]));
}

#[test]
fn messages_are_event_bound_unlike_legacy() {
    // Legacy: the signed hash depends only on the outcome string.
    assert_eq!(
        legacy::hash_attestation("paid"),
        legacy::hash_attestation("paid")
    );
    let pk = [9u8; 32];
    let ad = [1u8; 32];
    let r = [2u8; 32];
    let d_a = attestation_digest(&pk, "event-A", &ad, 0, &r, "paid").unwrap();
    let d_b = attestation_digest(&pk, "event-B", &ad, 0, &r, "paid").unwrap();
    assert_ne!(d_a, d_b);
    // index, R, announcement digest and oracle all matter
    assert_ne!(
        d_a,
        attestation_digest(&pk, "event-A", &ad, 1, &r, "paid").unwrap()
    );
    assert_ne!(
        d_a,
        attestation_digest(&pk, "event-A", &ad, 0, &[3; 32], "paid").unwrap()
    );
    assert_ne!(
        d_a,
        attestation_digest(&pk, "event-A", &[4; 32], 0, &r, "paid").unwrap()
    );
    assert_ne!(
        d_a,
        attestation_digest(&[8; 32], "event-A", &ad, 0, &r, "paid").unwrap()
    );
    // delimiter ambiguity that the legacy concatenation had: ("ab","c") vs ("a","bc")
    assert_ne!(
        attestation_digest(&pk, "ab", &ad, 0, &r, "c").unwrap(),
        attestation_digest(&pk, "a", &ad, 0, &r, "bc").unwrap()
    );
    // the legacy announcement serialisation has exactly that ambiguity
    assert_eq!(
        legacy::serialize_announcement("ab", "c", 0, &[]),
        legacy::serialize_announcement("a", "bc", 0, &[])
    );
}

#[test]
fn announcement_tampering_and_other_oracle_are_detected() {
    let mut o = oracle("tamper");
    let ann = o.announce("e", enum_desc(), MATURITY).unwrap();
    let mut t = ann.clone();
    t.maturity_time += 1;
    assert_eq!(t.verify(), Err(Error::SignatureInvalid));
    let mut t = ann.clone();
    t.nonce_points[0][0] ^= 1;
    assert!(t.verify().is_err());
    let mut t = ann.clone();
    t.descriptor = Descriptor::Enum {
        outcomes: vec!["a".into()],
    };
    assert!(t.verify().is_err());

    let mut other = oracle("other-oracle");
    other.announce("e", enum_desc(), MATURITY).unwrap();
    let att_other = other.attest_enum("e", 0, MATURITY).unwrap();
    assert!(verify_attestation(&ann, &att_other).is_err());
}

#[test]
fn announcements_are_unique_and_validated() {
    let mut o = oracle("uniq");
    let a = o.announce("e", enum_desc(), MATURITY).unwrap();
    assert!(matches!(
        o.announce("e", enum_desc(), MATURITY),
        Err(Error::Duplicate(_))
    ));
    assert!(o.announce("", enum_desc(), MATURITY).is_err());
    assert!(o.announce("has space", enum_desc(), MATURITY).is_err());
    assert!(o
        .announce("x", Descriptor::Enum { outcomes: vec![] }, MATURITY)
        .is_err());
    assert!(o
        .announce(
            "x",
            Descriptor::Enum {
                outcomes: vec!["a".into(), "a".into()]
            },
            MATURITY
        )
        .is_err());
    assert!(o.announce(&"e".repeat(129), enum_desc(), MATURITY).is_err());

    // a record that reuses an existing nonce commitment (even under a new event id) is refused
    let mut dup = a.clone();
    dup.event_id = "other".into();
    let tok = o.store_mut().acquire_writer("w").unwrap();
    let rec = EventAnnouncementRecord {
        announcement_hash: dup.digest().unwrap(),
        announcement: dup,
        attestation_id: None,
    };
    assert!(matches!(
        o.store_mut().reserve_announcement(&tok, rec),
        Err(Error::Duplicate("nonce commitment"))
    ));
}

#[test]
fn nonces_are_deterministic_per_event_and_distinct_across_events() {
    let mut o1 = oracle("det");
    let mut o2 = oracle("det");
    let a1 = o1.announce("same", numeric_desc(true), MATURITY).unwrap();
    let a2 = o2.announce("same", numeric_desc(true), MATURITY).unwrap();
    assert_eq!(a1.nonce_points, a2.nonce_points);
    assert_eq!(a1.signature, a2.signature);
    let mut seen = std::collections::BTreeSet::new();
    for r in &a1.nonce_points {
        assert!(seen.insert(*r));
    }
    let b = o1
        .announce("different", numeric_desc(true), MATURITY)
        .unwrap();
    for r in &b.nonce_points {
        assert!(!seen.contains(r));
    }
}
