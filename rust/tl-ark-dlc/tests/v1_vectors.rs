//! v1 message layouts checked against an independent Node derivation (scripts/v1-vectors.mjs).
//! The same digests appear as `decide` examples in lean/TlArkDlc/Binding.lean's documentation.

use serde_json::Value;
use tl_ark_dlc::attestation::{attestation_digest, Announcement, Descriptor, NumericDescriptor};
use tl_ark_dlc::handshake::{template_id_v2, ArkTemplate};
use tl_ark_dlc::util::{from_hex, hex32, to_hex};

fn v() -> Value {
    serde_json::from_str(include_str!("../fixtures/v1_vectors.json")).unwrap()
}

fn s<'a>(x: &'a Value, k: &str) -> &'a str {
    x[k].as_str().unwrap()
}

#[test]
fn attestation_digests_match_independent_derivation() {
    for a in v()["attestation_digest"].as_array().unwrap() {
        let got = attestation_digest(
            &hex32(s(a, "pk")).unwrap(),
            s(a, "event_id"),
            &hex32(s(a, "announcement_digest")).unwrap(),
            a["index"].as_u64().unwrap() as u32,
            &hex32(s(a, "r")).unwrap(),
            s(a, "outcome"),
        )
        .unwrap();
        assert_eq!(to_hex(&got), s(a, "digest"), "{}", s(a, "event_id"));
    }
    // the sample covers: same outcome under two events differs; delimiter shift differs
    let rows = v()["attestation_digest"].as_array().unwrap().clone();
    assert_ne!(rows[0]["digest"], rows[1]["digest"]);
    assert_ne!(rows[3]["digest"], rows[4]["digest"]);
}

#[test]
fn announcement_digests_match_independent_derivation() {
    for a in v()["announcement"].as_array().unwrap() {
        let descriptor = match s(a, "name") {
            "enum" => Descriptor::Enum {
                outcomes: vec!["fulfilled".into(), "defaulted".into(), "expired".into()],
            },
            "binary" => Descriptor::Binary {
                outcomes: ["paid".into(), "unpaid".into()],
            },
            _ => Descriptor::Numeric(NumericDescriptor {
                base: 2,
                num_digits: 2,
                unit: "USD".into(),
                precision: 0,
                signed: true,
            }),
        };
        assert_eq!(
            to_hex(&descriptor.encode().unwrap()),
            s(a, "descriptor_encoding")
        );
        let ann = Announcement {
            event_id: s(a, "event_id").to_string(),
            oracle_pubkey: hex32(s(a, "oracle")).unwrap(),
            descriptor,
            maturity_time: a["maturity"].as_u64().unwrap(),
            nonce_points: a["nonces"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| hex32(n.as_str().unwrap()).unwrap())
                .collect(),
            signature: [0; 64],
        };
        assert_eq!(
            to_hex(&ann.digest().unwrap()),
            s(a, "digest"),
            "{}",
            s(a, "name")
        );
    }
}

#[test]
fn template_v2_ids_match_independent_derivation() {
    let all = v();
    let rows = all["template_v2"].as_array().unwrap();
    for r in rows {
        let t = &r["template"];
        let strs = |k: &str| -> Vec<String> {
            t[k].as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect()
        };
        let tpl = ArkTemplate {
            version: t["version"].as_u64().unwrap() as u32,
            network: s(t, "network").to_string(),
            internal_key: s(t, "internal").to_string(),
            merkle_root: s(t, "root").to_string(),
            leaf_scripts: strs("scripts"),
            leaf_versions: t["versions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as u8)
                .collect(),
            leaf_roles: strs("roles"),
            timeouts: t["timeouts"].clone(),
            semantics: t["semantics"].clone(),
            taproot_output_key: None,
            template_id: None,
        };
        assert_eq!(
            template_id_v2(&tpl).unwrap(),
            s(r, "id"),
            "{}",
            s(r, "name")
        );
        assert!(from_hex(s(r, "id")).is_ok());
    }
    assert_eq!(rows[0]["id"], rows[1]["id"]); // order independent
    assert_ne!(rows[0]["id"], rows[2]["id"]); // pairing matters
    assert_ne!(rows[0]["id"], rows[3]["id"]); // network matters
}
