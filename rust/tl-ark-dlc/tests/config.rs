use std::collections::BTreeMap;
use tl_ark_dlc::config::*;

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn prod() -> Vec<(&'static str, &'static str)> {
    vec![
        ("NETWORK", "mainnet"),
        ("ORACLE_MODE", "production"),
        ("KEY_PROVIDER", "gcp"),
        ("CLOUD_PROJECT_ID", "proj"),
        ("REDIS_PASSWORD", "hunter2-redis"),
        ("API_AUTH_KEY", "0123456789abcdef0123"),
        ("CORS_ORIGINS", "https://app.example"),
        (
            "VTXO_SERVER_PUBKEY",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
    ]
}

fn errors(pairs: &[(&str, &str)]) -> Vec<String> {
    Config::from_map(&env(pairs)).unwrap_err().0
}

fn has(errs: &[String], needle: &str) -> bool {
    errs.iter().any(|e| e.contains(needle))
}

#[test]
fn development_defaults_load() {
    let c = Config::from_map(&env(&[])).unwrap();
    assert_eq!(c.network, NetworkType::Regtest);
    assert_eq!(c.mode, OracleMode::Development);
    assert_eq!(c.keys.provider, KeyProviderKind::Mock);
    assert_eq!(c.vtxo.default_exit_delay, 1008);
    assert_eq!(c.vtxo.min_contract_value, 10_000);
    assert_eq!(c.scheduler.announcement_lookahead, 13);
    assert_eq!(c.api.public_port, 3000);
    assert!(c.api.cors_enabled);
    assert_eq!(c.price_feeds, vec!["coingecko", "coinbase", "kraken"]);
    assert!(c.ethereum_networks.is_none());
    assert_eq!(c.api.auth_key.expose(), DEV_API_KEY);
}

#[test]
fn production_example_loads() {
    let c = Config::from_map(&env(&prod())).unwrap();
    assert_eq!(c.network.to_bitcoin(), bitcoin::Network::Bitcoin);
    assert_eq!(c.keys.provider, KeyProviderKind::Gcp);
    assert!(c.vtxo.server_pubkey.is_some());
    assert_eq!(c.api.cors_origins, vec!["https://app.example"]);
}

#[test]
fn legacy_fail_open_cases_now_fail_closed() {
    // legacy: unknown NETWORK / ORACLE_MODE / KEY_PROVIDER / LOG_LEVEL were cast, not checked
    assert!(has(&errors(&[("NETWORK", "mainet")]), "NETWORK"));
    assert!(has(&errors(&[("ORACLE_MODE", "prod")]), "ORACLE_MODE"));
    assert!(has(&errors(&[("KEY_PROVIDER", "hsm")]), "KEY_PROVIDER"));
    assert!(has(&errors(&[("LOG_LEVEL", "verbose")]), "LOG_LEVEL"));
    // legacy: parseInt("abc") = NaN and parseInt("12abc") = 12 both passed
    assert!(has(
        &errors(&[("PUBLIC_API_PORT", "abc")]),
        "PUBLIC_API_PORT"
    ));
    assert!(has(
        &errors(&[("PUBLIC_API_PORT", "12abc")]),
        "PUBLIC_API_PORT"
    ));
    assert!(has(&errors(&[("REDIS_PORT", "0")]), "REDIS_PORT"));
    assert!(has(&errors(&[("REDIS_PORT", "65536")]), "REDIS_PORT"));
    assert!(has(&errors(&[("VTXO_EXIT_DELAY", "0")]), "VTXO_EXIT_DELAY"));
    assert!(has(
        &errors(&[("VTXO_EXIT_DELAY", "65536")]),
        "VTXO_EXIT_DELAY"
    ));
    assert!(has(
        &errors(&[("MIN_CONTRACT_VALUE", "-1")]),
        "MIN_CONTRACT_VALUE"
    ));
    assert!(has(
        &errors(&[("MIN_CONTRACT_VALUE", "0")]),
        "MIN_CONTRACT_VALUE"
    ));
    assert!(has(
        &errors(&[("MONGODB_POOL_SIZE", "0")]),
        "MONGODB_POOL_SIZE"
    ));
    assert!(has(
        &errors(&[("PRICE_CHECK_INTERVAL", " 5")]),
        "PRICE_CHECK_INTERVAL"
    ));
    // legacy: CORS stayed enabled for any value except exactly "false"
    assert!(has(&errors(&[("CORS_ENABLED", "False")]), "CORS_ENABLED"));
    assert!(has(
        &errors(&[("ETHEREUM_ENABLED", "yes")]),
        "ETHEREUM_ENABLED"
    ));
    // legacy: empty URI / unknown scheme passed (only falsy was checked)
    assert!(has(&errors(&[("MONGODB_URI", "")]), "MONGODB_URI"));
    assert!(has(&errors(&[("MONGODB_URI", "http://x")]), "MONGODB_URI"));
    // legacy: any feed string accepted
    assert!(has(
        &errors(&[("PRICE_FEED_SOURCES", "coingecko,evil")]),
        "PRICE_FEED_SOURCES"
    ));
    assert!(has(
        &errors(&[("PRICE_FEED_SOURCES", "")]),
        "PRICE_FEED_SOURCES"
    ));
    assert!(has(
        &errors(&[("PUBLIC_API_PORT", "3000"), ("INTERNAL_API_PORT", "3000")]),
        "must differ"
    ));
}

#[test]
fn legacy_default_secrets_and_mock_keys_cannot_reach_production() {
    // mock provider by default outside development
    let e = errors(&[("ORACLE_MODE", "staging")]);
    assert!(has(&e, "KEY_PROVIDER is required"));
    // explicit mock outside development / on mainnet
    assert!(has(
        &errors(&[("ORACLE_MODE", "staging"), ("KEY_PROVIDER", "mock")]),
        "mock key provider"
    ));
    assert!(has(&errors(&[("NETWORK", "mainnet")]), "mock key provider"));
    // published API key: legacy rejected it only in production, never in staging
    let e = errors(&[
        ("ORACLE_MODE", "staging"),
        ("KEY_PROVIDER", "gcp"),
        ("CLOUD_PROJECT_ID", "p"),
        ("API_AUTH_KEY", DEV_API_KEY),
        ("CORS_ORIGINS", "https://a"),
        (
            "VTXO_SERVER_PUBKEY",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
    ]);
    assert!(has(&e, "API_AUTH_KEY"));
    // missing auth key outside development
    let mut p = prod();
    p.retain(|(k, _)| *k != "API_AUTH_KEY");
    assert!(has(&errors(&p), "API_AUTH_KEY is required"));
    // short key
    let mut p = prod();
    p.push(("API_AUTH_KEY", "short"));
    assert!(has(&errors(&p), "at least 16"));
    // wildcard CORS (legacy default "*") outside development
    let mut p = prod();
    p.push(("CORS_ORIGINS", "*"));
    assert!(has(&errors(&p), "wildcard CORS"));
    let mut p = prod();
    p.retain(|(k, _)| *k != "CORS_ORIGINS");
    assert!(has(&errors(&p), "CORS_ORIGINS is required"));
    // CORS disabled needs no origins
    let mut p = prod();
    p.retain(|(k, _)| *k != "CORS_ORIGINS");
    p.push(("CORS_ENABLED", "false"));
    Config::from_map(&env(&p)).unwrap();
    // redis password in production
    let mut p = prod();
    p.retain(|(k, _)| *k != "REDIS_PASSWORD");
    assert!(has(&errors(&p), "REDIS_PASSWORD"));
}

#[test]
fn provider_specific_requirements() {
    assert!(has(
        &errors(&[("KEY_PROVIDER", "local")]),
        "requires MNEMONIC"
    ));
    assert!(has(&errors(&[("KEY_PROVIDER", "aws")]), "CLOUD_PROJECT_ID"));
    assert!(has(
        &errors(&[("KEY_PROVIDER", "gcp"), ("CLOUD_PROJECT_ID", "")]),
        "must not be empty"
    ));
    let c = Config::from_map(&env(&[("KEY_PROVIDER", "local"), ("MNEMONIC", "abc def")])).unwrap();
    // secrets never print
    let dbg = format!("{c:?}");
    assert!(!dbg.contains("abc def"));
    assert!(dbg.contains("<redacted>"));
    // local mnemonics are refused in production / mainnet
    let mut p = prod();
    p.retain(|(k, _)| *k != "KEY_PROVIDER");
    p.push(("KEY_PROVIDER", "local"));
    p.push(("MNEMONIC", "abc def"));
    assert!(has(&errors(&p), "not allowed in production"));
}

#[test]
fn server_key_must_be_a_real_key_outside_development() {
    let mut p = prod();
    p.retain(|(k, _)| *k != "VTXO_SERVER_PUBKEY");
    assert!(has(&errors(&p), "VTXO_SERVER_PUBKEY is required"));
    for bad in [
        "zz",
        "00".repeat(32).as_str(),
        "05".repeat(33).as_str(),
        "79be",
    ] {
        let mut p = prod();
        p.retain(|(k, _)| *k != "VTXO_SERVER_PUBKEY");
        p.push(("VTXO_SERVER_PUBKEY", bad));
        assert!(
            has(&errors(&p), "VTXO_SERVER_PUBKEY must be a valid"),
            "{bad}"
        );
    }
    // a compressed key is accepted and reduced to x-only
    let mut p = prod();
    p.retain(|(k, _)| *k != "VTXO_SERVER_PUBKEY");
    p.push((
        "VTXO_SERVER_PUBKEY",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ));
    let c = Config::from_map(&env(&p)).unwrap();
    assert_eq!(c.vtxo.server_pubkey.unwrap()[0], 0x79);
    // in development an invalid key is still an error when supplied
    assert!(has(
        &errors(&[("VTXO_SERVER_PUBKEY", "nope")]),
        "VTXO_SERVER_PUBKEY"
    ));
}

#[test]
fn signet_is_not_testnet_and_all_errors_are_reported() {
    let c = Config::from_map(&env(&[("NETWORK", "signet")])).unwrap();
    assert_eq!(c.network.to_bitcoin(), bitcoin::Network::Signet);
    assert_ne!(c.network.to_bitcoin(), bitcoin::Network::Testnet);
    let e = errors(&[("NETWORK", "x"), ("LOG_LEVEL", "y"), ("REDIS_PORT", "z")]);
    assert_eq!(e.len(), 3);
    let msg = ConfigErrors(e).to_string();
    assert!(msg.starts_with("Configuration errors:"));
}

#[test]
fn rpc_and_ethereum_sections() {
    assert!(has(
        &errors(&[("BITCOIN_RPC_URL", "ftp://x")]),
        "BITCOIN_RPC_URL"
    ));
    assert!(has(
        &errors(&[("BITCOIN_RPC_URL", "http://x"), ("BITCOIN_RPC_USER", "u")]),
        "together"
    ));
    let c = Config::from_map(&env(&[
        ("BITCOIN_RPC_URL", "http://127.0.0.1:18443"),
        ("BITCOIN_RPC_USER", "u"),
        ("BITCOIN_RPC_PASSWORD", "p"),
        ("ETHEREUM_ENABLED", "true"),
        ("ETH_NETWORKS", "mainnet, sepolia"),
    ]))
    .unwrap();
    assert_eq!(c.ethereum_networks.unwrap(), vec!["mainnet", "sepolia"]);
    assert!(!format!("{:?}", c.bitcoin_rpc).contains("\"p\""));
    assert!(has(
        &errors(&[("ETHEREUM_ENABLED", "true"), ("ETH_NETWORKS", "mainnet,,x")]),
        "empty entry"
    ));
}
