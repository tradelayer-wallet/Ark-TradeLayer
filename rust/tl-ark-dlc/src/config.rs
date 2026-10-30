//! System configuration with fail-closed validation.
//!
//! Source: `vtxo-loan-system/src/config/system-config.ts`. The legacy loader cast arbitrary
//! environment strings to enums, accepted `parseInt` garbage (`NaN`, `12abc`), defaulted to the
//! mock key provider and the published API key `dev-key-insecure`, mapped signet to testnet and
//! enabled CORS for any value other than the exact string `false`. [`Config::from_map`] parses an
//! explicit environment map (no process access) and returns every violation, or a config that
//! satisfies all of them.

use std::collections::BTreeMap;
use std::fmt;

use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use bitcoin::Network;

use crate::util::{from_hex, hex32};

/// Published development API key that must never reach staging/production.
pub const DEV_API_KEY: &str = "dev-key-insecure";

/// A string that does not print itself.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Reveal the value (explicit at call sites).
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Bitcoin network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkType {
    /// Mainnet.
    Mainnet,
    /// Testnet.
    Testnet,
    /// Regtest.
    Regtest,
    /// Signet (legacy mapped it to testnet parameters).
    Signet,
}

impl NetworkType {
    /// Library network (signet stays signet).
    pub fn to_bitcoin(self) -> Network {
        match self {
            NetworkType::Mainnet => Network::Bitcoin,
            NetworkType::Testnet => Network::Testnet,
            NetworkType::Regtest => Network::Regtest,
            NetworkType::Signet => Network::Signet,
        }
    }
}

/// Operating mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleMode {
    /// Development.
    Development,
    /// Staging.
    Staging,
    /// Production.
    Production,
}

/// Key provider kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProviderKind {
    /// Local mnemonic.
    Local,
    /// GCP secret manager.
    Gcp,
    /// AWS secrets manager.
    Aws,
    /// Mock (synthetic keys).
    Mock,
}

/// Key management section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyConfig {
    /// Provider.
    pub provider: KeyProviderKind,
    /// Local mnemonic.
    pub mnemonic: Option<Secret>,
    /// Cloud project id.
    pub project_id: Option<String>,
    /// Cloud secret id.
    pub secret_id: String,
}

/// Database section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseConfig {
    /// URI (not logged: may contain credentials).
    pub uri: Secret,
    /// Database name.
    pub name: String,
    /// Pool size.
    pub pool_size: u32,
}

/// Redis section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedisConfig {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Password.
    pub password: Option<Secret>,
    /// Database index.
    pub db: u8,
}

/// Bitcoin RPC section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinRpcConfig {
    /// URL.
    pub url: String,
    /// User.
    pub user: Option<String>,
    /// Password.
    pub password: Option<Secret>,
}

/// API section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiConfig {
    /// Public port.
    pub public_port: u16,
    /// Internal port.
    pub internal_port: u16,
    /// Auth key.
    pub auth_key: Secret,
    /// CORS enabled.
    pub cors_enabled: bool,
    /// Allowed origins.
    pub cors_origins: Vec<String>,
}

/// Log level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    /// debug
    Debug,
    /// info
    Info,
    /// warn
    Warn,
    /// error
    Error,
}

/// Scheduler section (minutes / weeks as in the legacy config).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerConfig {
    /// Price check interval, minutes.
    pub price_check_interval: u32,
    /// Payment check interval, minutes.
    pub payment_check_interval: u32,
    /// Announcement lookahead, weeks.
    pub announcement_lookahead: u32,
}

/// VTXO section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VtxoConfig {
    /// Exit delay in blocks (BIP-68 range).
    pub default_exit_delay: u32,
    /// Server key (x-only), required outside development.
    pub server_pubkey: Option<[u8; 32]>,
    /// Minimum contract value in satoshis.
    pub min_contract_value: u64,
}

/// Validated configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Network.
    pub network: NetworkType,
    /// Mode.
    pub mode: OracleMode,
    /// Keys.
    pub keys: KeyConfig,
    /// Database.
    pub database: DatabaseConfig,
    /// Redis.
    pub redis: RedisConfig,
    /// Enabled price feeds.
    pub price_feeds: Vec<String>,
    /// Ethereum networks, when enabled.
    pub ethereum_networks: Option<Vec<String>>,
    /// Bitcoin RPC.
    pub bitcoin_rpc: Option<BitcoinRpcConfig>,
    /// API.
    pub api: ApiConfig,
    /// Log level.
    pub log_level: LogLevel,
    /// Scheduler.
    pub scheduler: SchedulerConfig,
    /// VTXO.
    pub vtxo: VtxoConfig,
}

/// All violations found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigErrors(pub Vec<String>);

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Configuration errors:\n{}", self.0.join("\n"))
    }
}

impl std::error::Error for ConfigErrors {}

struct P<'a> {
    env: &'a BTreeMap<String, String>,
    errs: Vec<String>,
}

impl<'a> P<'a> {
    fn get(&self, k: &str) -> Option<&'a str> {
        self.env.get(k).map(String::as_str)
    }
    fn err(&mut self, m: String) {
        self.errs.push(m);
    }
    fn num(&mut self, k: &str, default: u64, lo: u64, hi: u64) -> u64 {
        match self.get(k) {
            None => default,
            Some(s) => match s.parse::<u64>() {
                Ok(v) if (lo..=hi).contains(&v) => v,
                _ => {
                    self.err(format!("{k} must be an integer in {lo}..={hi}"));
                    default
                }
            },
        }
    }
    fn boolean(&mut self, k: &str, default: bool) -> bool {
        match self.get(k) {
            None => default,
            Some("true") => true,
            Some("false") => false,
            Some(_) => {
                self.err(format!("{k} must be exactly \"true\" or \"false\""));
                default
            }
        }
    }
    fn nonempty(&mut self, k: &str) -> Option<&'a str> {
        match self.get(k) {
            Some("") => {
                self.err(format!("{k} must not be empty when set"));
                None
            }
            other => other,
        }
    }
}

fn list(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.trim().to_string()).collect()
}

fn parse_server_key(s: &str) -> Option<[u8; 32]> {
    if s.len() == 64 {
        let b = hex32(s).ok()?;
        XOnlyPublicKey::from_slice(&b).ok()?;
        Some(b)
    } else if s.len() == 66 {
        let b = from_hex(s).ok()?;
        PublicKey::from_slice(&b)
            .ok()
            .map(|k| k.x_only_public_key().0.serialize())
    } else {
        None
    }
}

impl Config {
    /// Parse and validate. Never reads the process environment.
    pub fn from_map(env: &BTreeMap<String, String>) -> Result<Config, ConfigErrors> {
        let mut p = P {
            env,
            errs: Vec::new(),
        };

        let network = match p.get("NETWORK").unwrap_or("regtest") {
            "mainnet" => NetworkType::Mainnet,
            "testnet" => NetworkType::Testnet,
            "regtest" => NetworkType::Regtest,
            "signet" => NetworkType::Signet,
            _ => {
                p.err("NETWORK must be one of mainnet, testnet, regtest, signet".into());
                NetworkType::Regtest
            }
        };
        let mode = match p.get("ORACLE_MODE").unwrap_or("development") {
            "development" => OracleMode::Development,
            "staging" => OracleMode::Staging,
            "production" => OracleMode::Production,
            _ => {
                p.err("ORACLE_MODE must be one of development, staging, production".into());
                OracleMode::Production
            }
        };
        let dev = mode == OracleMode::Development;

        // keys
        let provider = match p.get("KEY_PROVIDER") {
            None if dev => KeyProviderKind::Mock,
            None => {
                p.err("KEY_PROVIDER is required outside development".into());
                KeyProviderKind::Mock
            }
            Some("local") => KeyProviderKind::Local,
            Some("gcp") => KeyProviderKind::Gcp,
            Some("aws") => KeyProviderKind::Aws,
            Some("mock") => KeyProviderKind::Mock,
            Some(_) => {
                p.err("KEY_PROVIDER must be one of local, gcp, aws, mock".into());
                KeyProviderKind::Mock
            }
        };
        let mnemonic = p.nonempty("MNEMONIC").map(|s| Secret(s.to_string()));
        let project_id = p.nonempty("CLOUD_PROJECT_ID").map(str::to_string);
        let secret_id = p
            .nonempty("CLOUD_SECRET_ID")
            .unwrap_or("oracle-mnemonic")
            .to_string();
        match provider {
            KeyProviderKind::Mock => {
                if !dev || network == NetworkType::Mainnet {
                    p.err("mock key provider is only allowed in development off mainnet".into());
                }
            }
            KeyProviderKind::Local => {
                if mnemonic.is_none() {
                    p.err("local key provider requires MNEMONIC".into());
                }
                if mode == OracleMode::Production || network == NetworkType::Mainnet {
                    p.err(
                        "local mnemonic provider is not allowed in production or on mainnet".into(),
                    );
                }
            }
            KeyProviderKind::Gcp | KeyProviderKind::Aws => {
                if project_id.is_none() {
                    p.err("cloud key provider requires CLOUD_PROJECT_ID".into());
                }
            }
        }

        // database
        let uri = p.get("MONGODB_URI").unwrap_or("mongodb://localhost:27017");
        if !(uri.starts_with("mongodb://") || uri.starts_with("mongodb+srv://")) {
            p.err("MONGODB_URI must start with mongodb:// or mongodb+srv://".into());
        }
        let db_name = p
            .nonempty("MONGODB_DATABASE")
            .unwrap_or("vtxo-loans")
            .to_string();
        let pool_size = p.num("MONGODB_POOL_SIZE", 10, 1, 500) as u32;

        // redis
        let host = p.nonempty("REDIS_HOST").unwrap_or("127.0.0.1").to_string();
        let port = p.num("REDIS_PORT", 6379, 1, 65_535) as u16;
        let db = p.num("REDIS_DB", 0, 0, 255) as u8;
        let redis_pw = p.nonempty("REDIS_PASSWORD").map(|s| Secret(s.to_string()));
        if mode == OracleMode::Production && redis_pw.is_none() {
            p.err("REDIS_PASSWORD is required in production".into());
        }

        // data sources
        let mut price_feeds = match p.get("PRICE_FEED_SOURCES") {
            None => vec![
                "coingecko".to_string(),
                "coinbase".to_string(),
                "kraken".to_string(),
            ],
            Some(s) => list(s),
        };
        if price_feeds.is_empty()
            || price_feeds
                .iter()
                .any(|f| !["coingecko", "coinbase", "kraken"].contains(&f.as_str()))
        {
            p.err(
                "PRICE_FEED_SOURCES must be a non-empty list of coingecko, coinbase, kraken".into(),
            );
            price_feeds = Vec::new();
        }
        let eth_enabled = p.boolean("ETHEREUM_ENABLED", false);
        let ethereum_networks = if eth_enabled {
            let nets = match p.get("ETH_NETWORKS") {
                None => vec!["mainnet".to_string(), "sepolia".to_string()],
                Some(s) => list(s),
            };
            if nets.iter().any(|n| n.is_empty()) {
                p.err("ETH_NETWORKS contains an empty entry".into());
            }
            Some(nets)
        } else {
            None
        };
        let bitcoin_rpc = match p.get("BITCOIN_RPC_URL") {
            None => None,
            Some(url) => {
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    p.err("BITCOIN_RPC_URL must be http(s)".into());
                }
                let user = p.nonempty("BITCOIN_RPC_USER").map(str::to_string);
                let pw = p
                    .nonempty("BITCOIN_RPC_PASSWORD")
                    .map(|s| Secret(s.to_string()));
                if user.is_some() != pw.is_some() {
                    p.err("BITCOIN_RPC_USER and BITCOIN_RPC_PASSWORD must be set together".into());
                }
                Some(BitcoinRpcConfig {
                    url: url.to_string(),
                    user,
                    password: pw,
                })
            }
        };

        // api
        let public_port = p.num("PUBLIC_API_PORT", 3000, 1, 65_535) as u16;
        let internal_port = p.num("INTERNAL_API_PORT", 3001, 1, 65_535) as u16;
        if public_port == internal_port {
            p.err("PUBLIC_API_PORT and INTERNAL_API_PORT must differ".into());
        }
        let auth_key = match p.nonempty("API_AUTH_KEY") {
            Some(k) => k.to_string(),
            None if dev => DEV_API_KEY.to_string(),
            None => {
                p.err("API_AUTH_KEY is required outside development".into());
                String::new()
            }
        };
        if !dev && (auth_key == DEV_API_KEY || (auth_key.len() < 16 && !auth_key.is_empty())) {
            p.err("API_AUTH_KEY must be a non-default key of at least 16 characters outside development".into());
        }
        let cors_enabled = p.boolean("CORS_ENABLED", true);
        let cors_origins = match p.get("CORS_ORIGINS") {
            None if dev => vec!["*".to_string()],
            None => Vec::new(),
            Some(s) => list(s),
        };
        if cors_enabled {
            if cors_origins.is_empty() && !dev {
                p.err("CORS_ORIGINS is required outside development when CORS is enabled".into());
            }
            for o in &cors_origins {
                let ok = o == "*" || o.starts_with("http://") || o.starts_with("https://");
                if !ok {
                    p.err(format!("CORS origin {o:?} must be * or an http(s) origin"));
                }
                if o == "*" && !dev {
                    p.err("wildcard CORS origin is not allowed outside development".into());
                }
            }
        }

        // monitoring
        let log_level = match p.get("LOG_LEVEL").unwrap_or("info") {
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            _ => {
                p.err("LOG_LEVEL must be one of debug, info, warn, error".into());
                LogLevel::Info
            }
        };

        // scheduler
        let scheduler = SchedulerConfig {
            price_check_interval: p.num("PRICE_CHECK_INTERVAL", 5, 1, 1440) as u32,
            payment_check_interval: p.num("PAYMENT_CHECK_INTERVAL", 2, 1, 1440) as u32,
            announcement_lookahead: p.num("ANNOUNCEMENT_LOOKAHEAD", 13, 1, 520) as u32,
        };

        // vtxo
        let default_exit_delay = p.num("VTXO_EXIT_DELAY", 1008, 1, 65_535) as u32;
        let min_contract_value = p.num("MIN_CONTRACT_VALUE", 10_000, 546, 2_100_000_000_000_000);
        let server_pubkey = match p.get("VTXO_SERVER_PUBKEY") {
            None | Some("") => {
                if !dev {
                    p.err("VTXO_SERVER_PUBKEY is required outside development".into());
                }
                None
            }
            Some(s) => {
                let k = parse_server_key(s);
                if k.is_none() {
                    p.err("VTXO_SERVER_PUBKEY must be a valid x-only (64 hex) or compressed (66 hex) key".into());
                }
                k
            }
        };

        if !p.errs.is_empty() {
            return Err(ConfigErrors(p.errs));
        }
        Ok(Config {
            network,
            mode,
            keys: KeyConfig {
                provider,
                mnemonic,
                project_id,
                secret_id,
            },
            database: DatabaseConfig {
                uri: Secret(uri.to_string()),
                name: db_name,
                pool_size,
            },
            redis: RedisConfig {
                host,
                port,
                password: redis_pw,
                db,
            },
            price_feeds,
            ethereum_networks,
            bitcoin_rpc,
            api: ApiConfig {
                public_port,
                internal_port,
                auth_key: Secret(auth_key),
                cors_enabled,
                cors_origins,
            },
            log_level,
            scheduler,
            vtxo: VtxoConfig {
                default_exit_delay,
                server_pubkey,
                min_contract_value,
            },
        })
    }
}
