//! Parity with vectors produced by running the REAL legacy code (scripts/compare-legacy.mjs,
//! pinned blob SHAs inside `fixtures/legacy_vectors.json`).

use serde_json::Value;
use tl_ark_dlc::attestation::{decompose_numeric, Descriptor, NumericDescriptor};
use tl_ark_dlc::handshake::{
    decode_witness_program, taproot_output_key, template_id_legacy, ArkTemplate,
};
use tl_ark_dlc::hash::tagged_hash;
use tl_ark_dlc::legacy;
use tl_ark_dlc::util::{from_hex, hex32, to_hex};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../fixtures/legacy_vectors.json")).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

#[test]
fn pins_are_recorded() {
    let v = vectors();
    let pins = v["pins"].as_object().unwrap();
    assert_eq!(pins.len(), 3);
    assert!(pins.values().all(|p| p.as_str().unwrap().len() == 40));
}

#[test]
fn tagged_hash_matches_legacy() {
    for t in vectors()["tagged_hash"].as_array().unwrap() {
        let got = tagged_hash(s(t, "tag"), &from_hex(s(t, "data")).unwrap());
        assert_eq!(to_hex(&got), s(t, "out"), "tag {}", s(t, "tag"));
    }
}

#[test]
fn hash_attestation_matches_legacy() {
    let v = vectors();
    let rows = v["hash_attestation"].as_array().unwrap();
    assert!(rows.len() >= 10);
    for t in rows {
        assert_eq!(
            to_hex(&legacy::hash_attestation(s(t, "outcome"))),
            s(t, "out")
        );
    }
}

#[test]
fn nonce_tweak_matches_legacy() {
    for t in vectors()["nonce_tweak"].as_array().unwrap() {
        let base = from_hex(s(t, "base")).unwrap();
        assert_eq!(
            to_hex(&legacy::derive_nonce_tweak(&base, s(t, "event_id"))),
            s(t, "out")
        );
    }
}

fn descriptor_for(name: &str) -> Descriptor {
    match name {
        "enum" => Descriptor::Enum {
            outcomes: vec!["fulfilled".into(), "defaulted".into(), "expired".into()],
        },
        "binary" => Descriptor::Binary {
            outcomes: ["paid".into(), "unpaid".into()],
        },
        _ => Descriptor::Numeric(NumericDescriptor {
            base: 2,
            num_digits: 8,
            unit: "USD".into(),
            precision: 0,
            signed: true,
        }),
    }
}

#[test]
fn announcement_serialisation_and_digest_match_legacy() {
    for a in vectors()["announcement"].as_array().unwrap() {
        let d = descriptor_for(s(a, "name"));
        assert_eq!(legacy::descriptor_json(&d), s(a, "descriptor_json"));
        assert_eq!(d.nonces_needed() as u64, a["nonce_count"].as_u64().unwrap());
        let nonces: Vec<[u8; 32]> = a["nonce_points"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| hex32(n.as_str().unwrap()).unwrap())
            .collect();
        let data = legacy::serialize_announcement(
            s(a, "event_id"),
            &legacy::descriptor_json(&d),
            a["maturity"].as_i64().unwrap(),
            &nonces,
        );
        assert_eq!(to_hex(&data), s(a, "data"));
        assert_eq!(to_hex(&legacy::hash_announcement(&data)), s(a, "digest"));
    }
}

#[test]
fn numeric_decomposition_matches_legacy() {
    for r in vectors()["numeric_decomposition"].as_array().unwrap() {
        let n = NumericDescriptor {
            base: r["base"].as_u64().unwrap() as u8,
            num_digits: r["num_digits"].as_u64().unwrap() as u16,
            unit: String::new(),
            precision: 0,
            signed: r["signed"].as_bool().unwrap(),
        };
        let got = decompose_numeric(r["value"].as_i64().unwrap(), &n);
        match &r["outcomes"] {
            Value::Array(exp) => {
                let exp: Vec<&str> = exp.iter().map(|x| x.as_str().unwrap()).collect();
                assert_eq!(got.unwrap(), exp);
            }
            _ => assert!(got.is_err(), "legacy threw: {:?}", r["outcomes"]),
        }
    }
}

#[test]
fn legacy_numeric_defect_probes_fail_closed_here() {
    // Legacy turned 1.5 and NaN into garbage digit strings ("." and "N", "a"); the Rust API takes
    // integers, and the outcome checker rejects such digits.
    let v = vectors();
    let probes = v["numeric_defect_probes"].as_array().unwrap();
    assert_eq!(probes.len(), 2);
    let d = Descriptor::Numeric(NumericDescriptor {
        base: 2,
        num_digits: 8,
        unit: String::new(),
        precision: 0,
        signed: false,
    });
    for p in probes {
        let legacy_out: Vec<String> = p["outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert!(d.check_outcomes(&legacy_out).is_err());
    }
}

fn template(v: &Value) -> ArkTemplate {
    let strs = |k: &str| -> Vec<String> {
        v[k].as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
    };
    ArkTemplate {
        version: v["version"].as_u64().unwrap() as u32,
        network: s(v, "network").to_string(),
        internal_key: s(v, "internalKey").to_string(),
        merkle_root: s(v, "merkleRoot").to_string(),
        leaf_scripts: strs("leafScripts"),
        leaf_versions: v["leafVersions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u8)
            .collect(),
        leaf_roles: strs("leafRoles"),
        timeouts: v["timeouts"].clone(),
        semantics: v["semantics"].clone(),
        taproot_output_key: None,
        template_id: None,
    }
}

#[test]
fn legacy_template_id_and_canonical_json_match() {
    let v = vectors();
    for t in v["template_id"].as_array().unwrap() {
        let tpl = template(&t["template"]);
        assert_eq!(
            legacy::canonical_json(&tpl.timeouts).to_string(),
            s(t, "canonical_timeouts")
        );
        assert_eq!(
            legacy::canonical_json(&tpl.semantics).to_string(),
            s(t, "canonical_semantics")
        );
        assert_eq!(
            template_id_legacy(&tpl).unwrap(),
            s(t, "id"),
            "{}",
            s(t, "name")
        );
    }
    for c in v["canonical_json"].as_array().unwrap() {
        let input: Value = serde_json::from_str(s(c, "input")).unwrap();
        assert_eq!(legacy::canonical_json(&input).to_string(), s(c, "out"));
    }
}

#[test]
fn legacy_template_id_collides_for_different_role_pairings() {
    // Repaired defect: the legacy id sorts scripts but not roles, so these two different
    // script/role pairings share an id. The v2 id (used by the registry) distinguishes them.
    let v = vectors();
    let rows = v["template_id"].as_array().unwrap();
    assert_eq!(s(&rows[0], "id"), s(&rows[1], "id"));
    assert_ne!(
        rows[0]["template"]["leafScripts"],
        rows[1]["template"]["leafScripts"]
    );
}

#[test]
fn segwit_decoding_agrees_with_legacy_except_trailing_bytes() {
    for r in vectors()["decode_segwit"].as_array().unwrap() {
        let script = from_hex(s(r, "script")).unwrap();
        let lenient = legacy::decode_segwit_lenient(&script);
        match r["out"]["error"].as_str() {
            Some(_) => assert!(lenient.is_err(), "{}", s(r, "script")),
            None => {
                let (ver, prog) = lenient.unwrap();
                assert_eq!(u64::from(ver), r["out"]["version"].as_u64().unwrap());
                assert_eq!(to_hex(&prog), r["out"]["program"].as_str().unwrap());
            }
        }
        let strict = decode_witness_program(&script);
        if s(r, "script").ends_with("ff") && script.len() == 35 {
            assert!(strict.is_err(), "trailing byte must be rejected");
        } else if let Ok((v1, p1)) = strict {
            let (v2, p2) = legacy::decode_segwit_lenient(&script).unwrap();
            assert_eq!((v1, p1.to_vec()), (v2, p2));
        }
    }
}

#[test]
fn legacy_placeholder_taproot_key_is_not_a_taproot_commitment() {
    let v = vectors();
    let p = &v["placeholder_taproot_key"];
    // legacy returned the internal key unchanged
    assert_eq!(s(p, "out"), s(p, "internal_key"));
    // the real BIP-341 key for an x-only internal key with this root differs from the internal key
    let internal = hex32(&s(p, "internal_key")[2..]).unwrap();
    let root = hex32(s(p, "merkle_root")).unwrap();
    let q = taproot_output_key(&internal, &root).unwrap();
    assert_ne!(q, internal);
}

#[test]
fn legacy_compact_size_throws_above_252() {
    for r in vectors()["compact_size"].as_array().unwrap() {
        let n = r["n"].as_u64().unwrap() as usize;
        let got = legacy::compact_size_legacy(n);
        match r["out"].as_str() {
            Some(h) => assert_eq!(to_hex(&got.unwrap()), h),
            None => assert!(got.is_err()),
        }
    }
}

#[test]
fn legacy_reconstruct_is_not_bip341() {
    let v = vectors();
    let r = &v["legacy_reconstruct"];
    // legacy "taproot key" is just the control block's internal key
    assert_eq!(s(r, "taprootOutputKey"), s(r, "internalKey"));
    // real verification (library) rejects this control block/leaf pair for any output key
    use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
    use bitcoin::taproot::ControlBlock;
    use bitcoin::ScriptBuf;
    let cb = ControlBlock::decode(&from_hex(s(r, "control_block")).unwrap());
    if let Ok(cb) = cb {
        let secp = Secp256k1::verification_only();
        let key = XOnlyPublicKey::from_slice(&from_hex(s(r, "internalKey")).unwrap()).unwrap();
        let script = ScriptBuf::from_bytes(from_hex(s(r, "leaf")).unwrap());
        assert!(!cb.verify_taproot_commitment(&secp, key, &script));
    }
}
