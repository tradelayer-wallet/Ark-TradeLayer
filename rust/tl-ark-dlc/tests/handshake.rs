use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{ScriptBuf, Txid};
use serde_json::json;
use tl_ark_dlc::handshake::*;
use tl_ark_dlc::hash::sha256_bytes;
use tl_ark_dlc::util::to_hex;
use tl_ark_dlc::Error;

fn xonly(label: &str) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&sha256_bytes(label.as_bytes())).unwrap();
    Keypair::from_secret_key(&secp, &sk).x_only_public_key().0
}

fn leaf(key: &XOnlyPublicKey, csv: &[u8]) -> Vec<u8> {
    // <key> OP_CHECKSIGVERIFY <csv> OP_CHECKSEQUENCEVERIFY (never executed here)
    let mut v = vec![0x20];
    v.extend_from_slice(&key.serialize());
    v.push(0xad);
    v.extend_from_slice(csv);
    v.push(0xb2);
    v
}

struct Tree {
    info: TaprootSpendInfo,
    scripts: Vec<Vec<u8>>, // batch-settle, user-exit, asp-forfeit
    internal: XOnlyPublicKey,
}

fn tree(internal_label: &str, user: &str) -> Tree {
    let secp = Secp256k1::new();
    let internal = xonly(internal_label);
    let scripts = vec![
        leaf(&xonly(user), &[0x01, 0x01]),
        leaf(&xonly(user), &[0x02, 0xf0, 0x03]),
        leaf(&xonly("asp"), &[0x02, 0xd0, 0x07]),
    ];
    let info = TaprootBuilder::new()
        .add_leaf(1, ScriptBuf::from_bytes(scripts[0].clone()))
        .unwrap()
        .add_leaf(2, ScriptBuf::from_bytes(scripts[1].clone()))
        .unwrap()
        .add_leaf(2, ScriptBuf::from_bytes(scripts[2].clone()))
        .unwrap()
        .finalize(&secp, internal)
        .unwrap();
    Tree {
        info,
        scripts,
        internal,
    }
}

fn template(t: &Tree) -> ArkTemplate {
    ArkTemplate {
        version: 1,
        network: "bitcoin-regtest".into(),
        internal_key: to_hex(&t.internal.serialize()),
        merkle_root: to_hex(&t.info.merkle_root().unwrap().to_byte_array()),
        leaf_scripts: t.scripts.iter().map(|s| to_hex(s)).collect(),
        leaf_versions: vec![0xc0; 3],
        leaf_roles: vec![
            "batch-settle".into(),
            "user-exit".into(),
            "asp-forfeit".into(),
        ],
        timeouts: json!({"userExitCsv": 1008, "aspForfeitCsv": 2000}),
        semantics: json!({"userExit": "unilateral exit", "aspForfeit": "server claims"}),
        taproot_output_key: Some(to_hex(
            &t.info.output_key().to_x_only_public_key().serialize(),
        )),
        template_id: None,
    }
}

fn txid(n: u8) -> Txid {
    Txid::from_byte_array([n; 32])
}

fn spk(t: &Tree) -> Vec<u8> {
    let mut v = vec![0x51, 0x20];
    v.extend_from_slice(&t.info.output_key().to_x_only_public_key().serialize());
    v
}

fn control_block(t: &Tree, idx: usize) -> Vec<u8> {
    t.info
        .control_block(&(
            ScriptBuf::from_bytes(t.scripts[idx].clone()),
            LeafVersion::TapScript,
        ))
        .unwrap()
        .serialize()
}

struct World {
    bridge: Bridge,
    chain: MemoryChain,
    tree: Tree,
    template_id: String,
}

fn world() -> World {
    let tree = tree("internal", "user");
    let mut reg = TemplateRegistry::new();
    let template_id = reg.register(template(&tree), "asp.example").unwrap();
    let mut chain = MemoryChain::default();
    chain.txs.insert(
        txid(1),
        TxView {
            confirmations: 6,
            inputs: vec![],
            outputs: vec![TxOutView {
                value_sats: 100_000,
                script_pubkey: spk(&tree),
            }],
        },
    );
    World {
        bridge: Bridge::new(reg),
        chain,
        tree,
        template_id,
    }
}

fn mint_req(w: &World) -> MintRequest {
    MintRequest {
        token: TokenKind::ArkVtxo,
        template_id: w.template_id.clone(),
        asp_id: "asp.example".into(),
        deposit_txid: txid(1),
        deposit_vout: 0,
        value_sats: 100_000,
    }
}

fn add_exit(w: &mut MemoryChain, witness: Vec<Vec<u8>>, out_sats: u64, confs: u32) {
    w.txs.insert(
        txid(2),
        TxView {
            confirmations: confs,
            inputs: vec![TxInView {
                prev_txid: txid(1),
                prev_vout: 0,
                witness,
            }],
            outputs: vec![TxOutView {
                value_sats: out_sats,
                script_pubkey: vec![0x51],
            }],
        },
    );
}

fn redeem_req() -> RedeemRequest {
    RedeemRequest {
        deposit_txid: txid(1),
        deposit_vout: 0,
        redeem_txid: txid(2),
        burn_amount_sats: 100_000,
    }
}

fn user_exit_witness(w: &World) -> Vec<Vec<u8>> {
    vec![
        vec![0xaa; 64],
        w.tree.scripts[1].clone(),
        control_block(&w.tree, 1),
    ]
}

#[test]
fn registration_uses_real_taproot_and_order_independent_ids() {
    let t = tree("internal", "user");
    let tpl = template(&t);
    let id = template_id_v2(&tpl).unwrap();

    // reordering leaves together with their roles/versions does not change the id
    let mut re = tpl.clone();
    re.leaf_scripts.reverse();
    re.leaf_roles.reverse();
    re.leaf_versions.reverse();
    assert_eq!(template_id_v2(&re).unwrap(), id);

    // pairing the same scripts with different roles does (legacy: same id)
    let mut swapped = tpl.clone();
    swapped.leaf_scripts.swap(0, 1); // roles and versions stay: a different script-to-role pairing
    assert_ne!(template_id_v2(&swapped).unwrap(), id);
    assert_eq!(
        template_id_legacy(&swapped).unwrap(),
        template_id_legacy(&tpl).unwrap()
    );

    // version, network and timeouts are bound
    let mut v = tpl.clone();
    v.network = "bitcoin-mainnet".into();
    assert_ne!(template_id_v2(&v).unwrap(), id);
    let mut v = tpl.clone();
    v.timeouts = json!({"userExitCsv": 1009, "aspForfeitCsv": 2000});
    assert_ne!(template_id_v2(&v).unwrap(), id);

    let mut reg = TemplateRegistry::new();
    assert_eq!(reg.register(tpl.clone(), "asp.example").unwrap(), id);
    assert!(reg.is_allowed(&id, "asp.example"));
    assert!(!reg.is_allowed(&id, "other-asp"));
    // idempotent for the same (template, asp)
    assert_eq!(reg.register(tpl.clone(), "asp.example").unwrap(), id);
    // the same output key cannot be re-bound to another ASP (legacy silently overwrote the index)
    assert!(matches!(
        reg.register(tpl, "attacker-asp"),
        Err(Error::Duplicate(_))
    ));
}

#[test]
fn registration_rejects_bad_templates() {
    let t = tree("internal", "user");
    let good = template(&t);
    let mut reg = TemplateRegistry::new();

    // the legacy placeholder "output key == internal key" is not a taproot commitment
    let mut p = good.clone();
    p.taproot_output_key = Some(p.internal_key.clone());
    assert_eq!(
        reg.register(p, "a"),
        Err(Error::Rejected("taproot output key mismatch"))
    );
    let mut p = good.clone();
    p.taproot_output_key = None;
    assert!(reg.register(p, "a").is_err());
    // declared id must match
    let mut p = good.clone();
    p.template_id = Some("00".repeat(32));
    assert!(reg.register(p, "a").is_err());
    // placeholder scripts from the legacy sample are not hex
    let mut p = good.clone();
    p.leaf_scripts[0] = "20<user_pk>ac20<server_pk>ac".into();
    assert!(reg.register(p, "a").is_err());
    // 33-byte (compressed) internal key from the legacy sample
    let mut p = good.clone();
    p.internal_key = format!("02{}", p.internal_key);
    assert!(reg.register(p, "a").is_err());
    // array length mismatch, duplicate roles, odd leaf version, float timeouts, unknown network
    let mut p = good.clone();
    p.leaf_versions.pop();
    assert!(reg.register(p, "a").is_err());
    let mut p = good.clone();
    p.leaf_roles[2] = "user-exit".into();
    assert!(reg.register(p, "a").is_err());
    let mut p = good.clone();
    p.leaf_versions[0] = 0xc1;
    assert!(reg.register(p, "a").is_err());
    let mut p = good.clone();
    p.timeouts = json!({"x": 1.5});
    assert!(reg.register(p, "a").is_err());
    let mut p = good.clone();
    p.network = "bitcoin-mainet".into();
    assert!(reg.register(p, "a").is_err());
    let mut p = good.clone();
    p.leaf_scripts.clear();
    p.leaf_versions.clear();
    p.leaf_roles.clear();
    assert!(reg.register(p, "a").is_err());
    // asp id must be an identifier
    assert!(reg.register(good, "bad asp").is_err());
}

#[test]
fn deposit_recognition_is_strict() {
    let w = world();
    let key = w.tree.info.output_key().to_x_only_public_key().serialize();
    let ok = spk(&w.tree);
    assert!(w.bridge.registry.recognize_commitment(&ok, 5).is_some());
    let mut trailing = ok.clone();
    trailing.push(0xff);
    assert!(w
        .bridge
        .registry
        .recognize_commitment(&trailing, 5)
        .is_none());
    let mut v0 = vec![0x00, 0x20];
    v0.extend_from_slice(&key);
    assert!(w.bridge.registry.recognize_commitment(&v0, 5).is_none());
    let mut v2 = vec![0x52, 0x20];
    v2.extend_from_slice(&key);
    assert!(w.bridge.registry.recognize_commitment(&v2, 5).is_none());
    let mut unknown = ok.clone();
    unknown[5] ^= 1;
    assert!(w
        .bridge
        .registry
        .recognize_commitment(&unknown, 5)
        .is_none());
    assert!(w.bridge.registry.recognize_commitment(&[], 5).is_none());
    assert!(w.bridge.registry.recognize_commitment(&[0x51], 5).is_none());
    assert!(w
        .bridge
        .registry
        .recognize_commitment(&[0x6a; 40], 5)
        .is_none());
}

#[test]
fn mint_happy_path_vout_zero_and_double_mint() {
    let mut w = world();
    let m = mint_req(&w);
    let out = w
        .bridge
        .handle(&w.chain, Message::WrapMint(m.clone()))
        .unwrap();
    match out {
        Outcome::Minted(c) => {
            assert_eq!(c.amount_sats, 100_000);
            assert_eq!(c.asp_id, "asp.example");
        }
        _ => panic!("expected mint"),
    }
    assert!(matches!(
        w.bridge.state(&txid(1), 0),
        Some(DepositState::Minted { .. })
    ));
    // the same deposit can never back a second mint
    assert_eq!(
        w.bridge.handle(&w.chain, Message::WrapMint(m)),
        Err(Error::Duplicate("deposit already minted"))
    );
}

#[test]
fn mint_rejections() {
    let mut w = world();
    let base = mint_req(&w);

    let mut m = base.clone();
    m.value_sats = 99_999;
    assert_eq!(
        w.bridge.handle(&w.chain, Message::WrapMint(m)),
        Err(Error::Rejected("amount mismatch"))
    );
    let mut m = base.clone();
    m.template_id = "00".repeat(32);
    assert_eq!(
        w.bridge.handle(&w.chain, Message::WrapMint(m)),
        Err(Error::Rejected("template not in allowlist"))
    );
    let mut m = base.clone();
    m.asp_id = "other".into();
    assert!(w.bridge.handle(&w.chain, Message::WrapMint(m)).is_err());
    let mut m = base.clone();
    m.deposit_vout = 1;
    assert!(w.bridge.handle(&w.chain, Message::WrapMint(m)).is_err());
    let mut m = base.clone();
    m.deposit_txid = txid(77);
    assert!(w.bridge.handle(&w.chain, Message::WrapMint(m)).is_err());

    // not enough confirmations
    w.chain.txs.get_mut(&txid(1)).unwrap().confirmations = 5;
    assert_eq!(
        w.bridge.handle(&w.chain, Message::WrapMint(base.clone())),
        Err(Error::Rejected("insufficient confirmations"))
    );
    w.chain.txs.get_mut(&txid(1)).unwrap().confirmations = 6;
    // already spent
    w.chain.spent.insert((txid(1), 0));
    assert_eq!(
        w.bridge.handle(&w.chain, Message::WrapMint(base.clone())),
        Err(Error::Rejected("UTXO already spent"))
    );
    w.chain.spent.clear();
    // failed attempts left no state behind, so the valid mint still works
    assert!(w.bridge.state(&txid(1), 0).is_none());
    w.bridge.handle(&w.chain, Message::WrapMint(base)).unwrap();
}

#[test]
fn redeem_through_user_exit_leaf() {
    let mut w = world();
    // no mint yet
    let wit = user_exit_witness(&w);
    add_exit(&mut w.chain, wit, 95_000, 6);
    assert!(matches!(
        w.bridge.handle(&w.chain, Message::Redeem(redeem_req())),
        Err(Error::NotFound(_))
    ));
    w.bridge
        .handle(&w.chain, Message::WrapMint(mint_req(&w)))
        .unwrap();
    let out = w
        .bridge
        .handle(&w.chain, Message::Redeem(redeem_req()))
        .unwrap();
    assert_eq!(
        out,
        Outcome::Redeemed {
            released_value_sats: 95_000
        }
    );
    assert!(matches!(
        w.bridge.state(&txid(1), 0),
        Some(DepositState::Burned { .. })
    ));
    // terminal: no second redeem, no re-mint
    assert_eq!(
        w.bridge.handle(&w.chain, Message::Redeem(redeem_req())),
        Err(Error::Duplicate("deposit already redeemed"))
    );
    assert!(w
        .bridge
        .handle(&w.chain, Message::WrapMint(mint_req(&w)))
        .is_err());
}

#[test]
fn redeem_accepts_a_taproot_annex() {
    let mut w = world();
    w.bridge
        .handle(&w.chain, Message::WrapMint(mint_req(&w)))
        .unwrap();
    let mut wit = user_exit_witness(&w);
    wit.push(vec![0x50, 0x01, 0x02]);
    add_exit(&mut w.chain, wit, 100_000, 6);
    w.bridge
        .handle(&w.chain, Message::Redeem(redeem_req()))
        .unwrap();
}

#[test]
fn redeem_rejections() {
    let mut w = world();
    w.bridge
        .handle(&w.chain, Message::WrapMint(mint_req(&w)))
        .unwrap();
    let good = user_exit_witness(&w);

    // key-path spend
    add_exit(&mut w.chain, vec![vec![0xaa; 64]], 100_000, 6);
    assert_eq!(
        w.bridge.handle(&w.chain, Message::Redeem(redeem_req())),
        Err(Error::Rejected("key-path spend (not a user exit)"))
    );
    // empty witness
    add_exit(&mut w.chain, vec![], 100_000, 6);
    assert!(w
        .bridge
        .handle(&w.chain, Message::Redeem(redeem_req()))
        .is_err());
    // the cooperative batch-settle leaf is a valid commitment but not a user exit
    add_exit(
        &mut w.chain,
        vec![
            vec![0xaa; 64],
            w.tree.scripts[0].clone(),
            control_block(&w.tree, 0),
        ],
        100_000,
        6,
    );
    assert_eq!(
        w.bridge.handle(&w.chain, Message::Redeem(redeem_req())),
        Err(Error::Rejected("leaf script is not a user-exit leaf"))
    );
    // an attacker's own tree with the same user-exit script but a different internal key
    let evil = tree("evil-internal", "user");
    add_exit(
        &mut w.chain,
        vec![
            vec![0xaa; 64],
            evil.scripts[1].clone(),
            control_block(&evil, 1),
        ],
        100_000,
        6,
    );
    assert!(w
        .bridge
        .handle(&w.chain, Message::Redeem(redeem_req()))
        .is_err());
    // legacy-style forgery: control block "internal key" set to the registered output key
    let key = w.tree.info.output_key().to_x_only_public_key().serialize();
    let mut forged = vec![0xc0];
    forged.extend_from_slice(&key);
    add_exit(
        &mut w.chain,
        vec![vec![0xaa; 64], w.tree.scripts[1].clone(), forged],
        100_000,
        6,
    );
    assert!(w
        .bridge
        .handle(&w.chain, Message::Redeem(redeem_req()))
        .is_err());
    // garbage control blocks
    for cb in [
        vec![],
        vec![0xc0; 5],
        vec![0xc0; 34],
        vec![0xc0; 33 + 32 * 129],
    ] {
        add_exit(
            &mut w.chain,
            vec![vec![1], w.tree.scripts[1].clone(), cb],
            100_000,
            6,
        );
        assert!(w
            .bridge
            .handle(&w.chain, Message::Redeem(redeem_req()))
            .is_err());
    }
    // right witness, but the exit transaction is not confirmed (legacy accepted it)
    add_exit(&mut w.chain, good.clone(), 100_000, 0);
    assert_eq!(
        w.bridge.handle(&w.chain, Message::Redeem(redeem_req())),
        Err(Error::Rejected(
            "exit transaction not sufficiently confirmed"
        ))
    );
    // too little value released (more than the 10_000 sat tolerance below the burn)
    add_exit(&mut w.chain, good.clone(), 89_999, 6);
    assert_eq!(
        w.bridge.handle(&w.chain, Message::Redeem(redeem_req())),
        Err(Error::Rejected("released value less than burn amount"))
    );
    // burn amount must equal the minted amount
    add_exit(&mut w.chain, good.clone(), 100_000, 6);
    let mut r = redeem_req();
    r.burn_amount_sats = 50_000;
    assert!(w.bridge.handle(&w.chain, Message::Redeem(r)).is_err());
    // the exit transaction must actually spend the deposit
    let mut r = redeem_req();
    r.redeem_txid = txid(55);
    assert!(w.bridge.handle(&w.chain, Message::Redeem(r)).is_err());
    // boundary: exactly at the tolerance is accepted
    add_exit(&mut w.chain, good, 90_000, 6);
    w.bridge
        .handle(&w.chain, Message::Redeem(redeem_req()))
        .unwrap();
}

#[test]
fn released_value_sum_is_checked() {
    let mut w = world();
    w.bridge
        .handle(&w.chain, Message::WrapMint(mint_req(&w)))
        .unwrap();
    let wit = user_exit_witness(&w);
    add_exit(&mut w.chain, wit, u64::MAX, 6);
    w.chain
        .txs
        .get_mut(&txid(2))
        .unwrap()
        .outputs
        .push(TxOutView {
            value_sats: 1,
            script_pubkey: vec![],
        });
    assert_eq!(
        w.bridge.handle(&w.chain, Message::Redeem(redeem_req())),
        Err(Error::Overflow)
    );
}

#[test]
fn wire_field_helpers() {
    assert_eq!(pick_vout(Some(0), None), Ok(0));
    assert_eq!(pick_vout(None, Some(0)), Ok(0));
    assert_eq!(pick_vout(Some(3), Some(3)), Ok(3));
    assert!(pick_vout(Some(1), Some(2)).is_err());
    assert!(pick_vout(None, None).is_err());
    assert_eq!(TokenKind::parse("dlc-vtxo"), Ok(TokenKind::DlcVtxo));
    assert_eq!(TokenKind::parse("ark-vtxo"), Ok(TokenKind::ArkVtxo));
    assert!(TokenKind::parse("ARK-VTXO").is_err());
    assert!(TokenKind::parse("").is_err());
}

#[test]
fn witness_program_decoder_bounds() {
    assert!(decode_witness_program(&[]).is_err());
    assert!(decode_witness_program(&[0x51, 0x01, 0xaa]).is_err()); // push too short
    let mut v0_bad = vec![0x00, 0x15];
    v0_bad.extend_from_slice(&[0; 21]);
    assert!(decode_witness_program(&v0_bad).is_err()); // v0 needs 20 or 32
    let mut v1 = vec![0x51, 0x28];
    v1.extend_from_slice(&[7; 40]);
    assert_eq!(decode_witness_program(&v1).unwrap().1.len(), 40);
    v1.push(0);
    assert!(decode_witness_program(&v1).is_err());
}
