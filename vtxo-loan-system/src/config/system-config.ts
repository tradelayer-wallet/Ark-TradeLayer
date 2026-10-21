/**
 * System Configuration
 * 
 * Centralized configuration management for the VTXO loan system.
 */

import * as path from "path";

import { BitcoinNetwork, BitcoinNetworks } from "bitcoin-networks";

/**
 * Supported Bitcoin networks
 */
export type NetworkType = "mainnet" | "testnet" | "regtest" | "signet";

/**
 * Oracle operating modes
 */
export type OracleMode = "development" | "staging" | "production";

/**
 * Key management configuration
 */
export interface KeyManagementConfig {
  /** Provider type */
  provider: "local" | "gcp" | "aws" | "mock";
  /** For local: mnemonic phrase */
  mnemonic?: string;
  /** For cloud: project/account ID */
  projectId?: string;
  /** For cloud: secret identifier */
  secretId?: string;
  /**
   * Explicit opt-in required to use the "local" key provider outside
   * development (set ALLOW_LOCAL_KEYS=1). Local mnemonics sitting in the
   * process environment are not acceptable key custody for real funds.
   */
  allowLocalKeys?: boolean;
}

/**
 * Database configuration
 */
export interface DatabaseConfig {
  /** MongoDB connection URI */
  uri: string;
  /** Database name */
  database: string;
  /** Connection pool size */
  poolSize?: number;
}

/**
 * Redis configuration for job queue
 */
export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  db?: number;
}

/**
 * External data source configuration
 */
export interface ExternalDataConfig {
  /** Price data sources */
  priceFeeds: {
    coinGeckoApiKey?: string;
    coinbaseApiKey?: string;
    enabled: string[]; // e.g., ["coingecko", "coinbase", "kraken"]
  };
  /** Blockchain data sources */
  blockchainClients: {
    /** Ethereum RPC configuration */
    ethereum?: {
      alchemyApiKey?: string;
      infuraApiKey?: string;
      networks: string[]; // e.g., ["mainnet", "sepolia"]
    };
    /** Bitcoin RPC configuration */
    bitcoin?: {
      rpcUrl: string;
      rpcUser?: string;
      rpcPassword?: string;
    };
  };
}

/**
 * API server configuration
 */
export interface ApiConfig {
  /** Public API port */
  publicPort: number;
  /** Internal admin API port */
  internalPort: number;
  /** API authentication key */
  authKey: string;
  /** CORS configuration */
  cors: {
    enabled: boolean;
    origins: string[];
  };
}

/**
 * Monitoring and alerting configuration
 */
export interface MonitoringConfig {
  /** Sentry DSN for error tracking */
  sentryDsn?: string;
  /** Slack webhook for alerts */
  slackWebhook?: string;
  /** Log level */
  logLevel: "debug" | "info" | "warn" | "error";
}

/**
 * Attestation scheduler configuration
 */
export interface SchedulerConfig {
  /** Price check interval (minutes) */
  priceCheckInterval: number;
  /** Payment check interval (minutes) */
  paymentCheckInterval: number;
  /** Announcement lookahead (weeks) */
  announcementLookahead: number;
}

/**
 * VTXO contract configuration
 */
export interface VtxoConfig {
  /** Default exit timelock (blocks) */
  defaultExitDelay: number;
  /** Server public key for cooperative paths */
  serverPublicKey: string;
  /** Minimum contract value (satoshis) */
  minContractValue: number;
}

/**
 * Main system configuration
 */
export interface SystemConfig {
  /** Bitcoin network */
  network: NetworkType;
  /** Oracle operating mode */
  mode: OracleMode;
  /** Key management */
  keys: KeyManagementConfig;
  /** Database */
  database: DatabaseConfig;
  /** Redis job queue */
  redis: RedisConfig;
  /** External data sources */
  externalData: ExternalDataConfig;
  /** API server */
  api: ApiConfig;
  /** Monitoring */
  monitoring: MonitoringConfig;
  /** Scheduler */
  scheduler: SchedulerConfig;
  /** VTXO contracts */
  vtxo: VtxoConfig;
  /** Used-nonce registry file (USED_NONCE_REGISTRY_PATH); must be an absolute path */
  usedNonceRegistryPath: string;
  /** Create the registry on this start if none exists (USED_NONCE_REGISTRY_INIT=1) */
  usedNonceRegistryInit: boolean;
}

/**
 * Insecure placeholder API key shipped in .env.example. Never acceptable
 * outside development.
 */
export const DEFAULT_API_AUTH_KEY = "dev-key-insecure";

/** Allowlisted key-custody providers */
export const KEY_PROVIDERS = ["local", "gcp", "aws", "mock"] as const;
/** Allowlisted Bitcoin networks */
export const NETWORK_TYPES = ["mainnet", "testnet", "regtest", "signet"] as const;
/** Allowlisted oracle operating modes */
export const ORACLE_MODES = ["development", "staging", "production"] as const;

/** Minimum length of API_AUTH_KEY outside development (non-whitespace characters) */
export const MIN_API_AUTH_KEY_LENGTH = 16;

/**
 * The single normalization rule for every enum-valued setting: trim, lowercase,
 * then require membership in the allowlist. Anything else throws, always.
 *
 * Strict comparison of raw strings was bypassable: KEY_PROVIDER=Mock, MOCK,
 * " mock" or NETWORK=Mainnet skipped the fail-closed checks.
 */
function normalizeEnum<T extends string>(raw: unknown, allowed: readonly T[], label: string): T {
  const normalized = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  if (!(allowed as readonly string[]).includes(normalized)) {
    throw new Error(
      `Unrecognized ${label} ${JSON.stringify(raw)}; allowed values: ${allowed.join(", ")}`
    );
  }
  return normalized as T;
}

/** Normalizes and validates a KEY_PROVIDER value (see normalizeEnum) */
export function normalizeKeyProvider(raw: unknown): KeyManagementConfig["provider"] {
  return normalizeEnum(raw, KEY_PROVIDERS, "KEY_PROVIDER");
}

/**
 * Canonical form of a configuration: every enum-valued field normalized, or
 * a throw. validateConfig and loadConfig both go through this function, which
 * is the one place config values are normalized.
 */
export function normalizeConfig(raw: SystemConfig): SystemConfig {
  return {
    ...raw,
    network: normalizeEnum(raw.network, NETWORK_TYPES, "network"),
    mode: normalizeEnum(raw.mode, ORACLE_MODES, "mode"),
    keys: { ...raw.keys, provider: normalizeKeyProvider(raw.keys.provider) },
  };
}

/**
 * The single API_AUTH_KEY policy. Returns the reason the key is unacceptable,
 * or null. Enforced outside development (mainnet implies outside development).
 * Whitespace does not count toward the length: " " or "   " are refused.
 */
export function apiAuthKeyViolation(authKey: unknown): string | null {
  if (typeof authKey !== "string") {
    return "API_AUTH_KEY must be a string";
  }
  // Both rules read the same normalized form (whitespace removed), so a placeholder
  // with stray whitespace or another letter case is still recognized.
  const significant = authKey.replace(/\s/g, "");
  if (significant.toLowerCase() === DEFAULT_API_AUTH_KEY) {
    return "API_AUTH_KEY is the insecure default";
  }
  if (significant.length < MIN_API_AUTH_KEY_LENGTH) {
    return (
      `API_AUTH_KEY must have at least ${MIN_API_AUTH_KEY_LENGTH} non-whitespace ` +
      `characters (got ${significant.length})`
    );
  }
  return null;
}

/** Range of a port number: 0 is not a port, and no port exceeds 65535 */
const PORT_RANGE = { min: 1, max: 65535 } as const;

/**
 * Reads a numeric setting: a plain decimal integer within [min, max], surrounding
 * whitespace allowed. A value such as "1e4" or "1008abc" is refused rather than
 * truncated, and a value outside the range is refused rather than loaded, so every
 * numeric setting goes through this one parser with its own range.
 */
function integerEnv(
  name: string,
  fallback: string,
  { min = 0, max = Number.MAX_SAFE_INTEGER }: { min?: number; max?: number } = {}
): number {
  const raw = process.env[name] || fallback;
  const text = raw.trim();
  const value = /^\d+$/.test(text) ? Number(text) : NaN;
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(
      `${name} must be an integer from ${min} to ${max}, got ${JSON.stringify(process.env[name])}`
    );
  }
  return value;
}

/**
 * Loads configuration from environment variables.
 *
 * Values are read as given. Enum-valued settings (NETWORK, ORACLE_MODE,
 * KEY_PROVIDER) are normalized and checked by validateConfig / loadConfig, not
 * here, so there is exactly one normalization point.
 */
export function loadConfigFromEnv(): SystemConfig {
  const networkType = (process.env.NETWORK || "regtest") as NetworkType;
  const mode = (process.env.ORACLE_MODE || "development") as OracleMode;

  const keys: KeyManagementConfig = {
    provider: (process.env.KEY_PROVIDER || "mock") as KeyManagementConfig["provider"],
    mnemonic: process.env.MNEMONIC,
    projectId: process.env.CLOUD_PROJECT_ID,
    secretId: process.env.CLOUD_SECRET_ID || "oracle-mnemonic",
    allowLocalKeys: process.env["ALLOW_LOCAL_KEYS"] === "1",
  };

  // Database
  const database: DatabaseConfig = {
    uri: process.env.MONGODB_URI || "mongodb://localhost:27017",
    database: process.env.MONGODB_DATABASE || "vtxo-loans",
    poolSize: integerEnv("MONGODB_POOL_SIZE", "10"),
  };

  // Redis
  const redis: RedisConfig = {
    host: process.env.REDIS_HOST || "127.0.0.1",
    port: integerEnv("REDIS_PORT", "6379", PORT_RANGE),
    password: process.env.REDIS_PASSWORD,
    db: integerEnv("REDIS_DB", "0"),
  };

  // External data sources
  const externalData: ExternalDataConfig = {
    priceFeeds: {
      coinGeckoApiKey: process.env.COINGECKO_API_KEY,
      coinbaseApiKey: process.env.COINBASE_API_KEY,
      enabled: (process.env.PRICE_FEED_SOURCES || "coingecko,coinbase,kraken").split(","),
    },
    blockchainClients: {
      ethereum: process.env.ETHEREUM_ENABLED === "true" ? {
        alchemyApiKey: process.env.ALCHEMY_API_KEY,
        infuraApiKey: process.env.INFURA_API_KEY,
        networks: (process.env.ETH_NETWORKS || "mainnet,sepolia").split(","),
      } : undefined,
      bitcoin: process.env.BITCOIN_RPC_URL ? {
        rpcUrl: process.env.BITCOIN_RPC_URL,
        rpcUser: process.env.BITCOIN_RPC_USER,
        rpcPassword: process.env.BITCOIN_RPC_PASSWORD,
      } : undefined,
    },
  };

  // API server
  const api: ApiConfig = {
    publicPort: integerEnv("PUBLIC_API_PORT", "3000", PORT_RANGE),
    internalPort: integerEnv("INTERNAL_API_PORT", "3001", PORT_RANGE),
    authKey: process.env.API_AUTH_KEY || DEFAULT_API_AUTH_KEY,
    cors: {
      enabled: process.env.CORS_ENABLED !== "false",
      origins: (process.env.CORS_ORIGINS || "*").split(","),
    },
  };

  // Monitoring
  const monitoring: MonitoringConfig = {
    sentryDsn: process.env.SENTRY_DSN,
    slackWebhook: process.env.SLACK_WEBHOOK,
    logLevel: (process.env.LOG_LEVEL || "info") as any,
  };

  // Scheduler
  const scheduler: SchedulerConfig = {
    priceCheckInterval: integerEnv("PRICE_CHECK_INTERVAL", "5"),
    paymentCheckInterval: integerEnv("PAYMENT_CHECK_INTERVAL", "2"),
    announcementLookahead: integerEnv("ANNOUNCEMENT_LOOKAHEAD", "13"),
  };

  // VTXO
  const vtxo: VtxoConfig = {
    defaultExitDelay: integerEnv("VTXO_EXIT_DELAY", "1008"),
    serverPublicKey: process.env.VTXO_SERVER_PUBKEY || "",
    minContractValue: integerEnv("MIN_CONTRACT_VALUE", "10000"),
  };

  return {
    network: networkType,
    mode,
    keys,
    database,
    redis,
    externalData,
    api,
    monitoring,
    scheduler,
    vtxo,
    usedNonceRegistryPath: (process.env["USED_NONCE_REGISTRY_PATH"] || "").trim(),
    usedNonceRegistryInit: registryInitEnv(),
  };
}

/**
 * USED_NONCE_REGISTRY_INIT: 1 creates the nonce registry on this start when none
 * exists at its path; unset or 0 does not. Any other value is refused.
 */
function registryInitEnv(): boolean {
  const text = (process.env["USED_NONCE_REGISTRY_INIT"] || "0").trim();
  if (text !== "0" && text !== "1") {
    throw new Error(
      `USED_NONCE_REGISTRY_INIT must be 1 or 0, got ${JSON.stringify(process.env["USED_NONCE_REGISTRY_INIT"])}`
    );
  }
  return text === "1";
}

/**
 * Converts network type to BitcoinNetwork object
 */
export function getBitcoinNetwork(networkType: NetworkType): BitcoinNetwork {
  switch (networkType) {
    case "mainnet":
      return BitcoinNetworks.bitcoin;
    case "testnet":
      return BitcoinNetworks.bitcoin_testnet;
    case "regtest":
      return BitcoinNetworks.bitcoin_regtest;
    case "signet":
      return BitcoinNetworks.bitcoin_testnet; // Use testnet params for signet
    default:
      throw new Error(`Unknown network type: ${networkType}`);
  }
}

/**
 * Validates configuration
 *
 * Security-critical misconfigurations (insecure key custody, default
 * credentials outside development) are fail-closed: they THROW here instead
 * of being returned as soft errors that a caller could ignore.
 */
export function validateConfig(input: SystemConfig): string[] {
  // Normalization happens here, through normalizeConfig: an unrecognized
  // network, mode or provider throws, so it can never be returned as a soft
  // error that a caller might ignore while the security checks run on it.
  const config = normalizeConfig(input);
  const errors: string[] = [];
  const critical: string[] = [];

  // --- Fail-closed security checks (C3) ---------------------------------
  // Insecure key custody must never leave development, and never touch mainnet.
  // MAINNET ALWAYS IMPLIES OUTSIDE-DEVELOPMENT: production semantics cannot
  // be weakened by setting ORACLE_MODE=development against a mainnet network.
  const outsideDevelopment = config.mode !== "development" || config.network === "mainnet";
  const provider = config.keys.provider;

  if (provider === "mock" && outsideDevelopment) {
    critical.push(
      `KEY_PROVIDER=mock derives keys from a world-known test seed; refusing to run ` +
        `with mode=${config.mode} network=${config.network}. Use a cloud KMS provider.`
    );
  }

  if (provider === "local") {
    if (config.network === "mainnet") {
      // No opt-out on mainnet: a mnemonic in process memory/env is not key
      // custody for real funds, not even with ALLOW_LOCAL_KEYS=1.
      critical.push(
        `KEY_PROVIDER=local keeps the mnemonic in process memory/env; refusing to run ` +
          `with network=mainnet (ALLOW_LOCAL_KEYS=1 does not apply on mainnet). Use a ` +
          `cloud KMS provider.`
      );
    } else if (!config.keys.allowLocalKeys && outsideDevelopment) {
      critical.push(
        `KEY_PROVIDER=local keeps the mnemonic in process memory/env; refusing to run ` +
          `with mode=${config.mode} network=${config.network}. Set ALLOW_LOCAL_KEYS=1 to ` +
          `explicitly accept this risk, or use a cloud KMS provider.`
      );
    }
  }

  // API_AUTH_KEY policy (default key refused; minimum strength)
  const authKeyProblem = apiAuthKeyViolation(config.api.authKey);
  if (outsideDevelopment && authKeyProblem !== null) {
    critical.push(
      `${authKeyProblem}; refusing to run with mode=${config.mode} network=${config.network}. ` +
        `Set a strong API_AUTH_KEY.`
    );
  }

  if (critical.length > 0) {
    throw new Error(`Fatal configuration errors (refusing to start):\n${critical.join("\n")}`);
  }
  // ----------------------------------------------------------------------

  // Validate key management
  if (provider === "local" && !config.keys.mnemonic) {
    errors.push("Local key provider requires MNEMONIC environment variable");
  }

  if (provider === "gcp" || provider === "aws") {
    if (!config.keys.projectId) {
      errors.push(`Cloud provider requires CLOUD_PROJECT_ID`);
    }
  }

  // Validate database
  if (!config.database.uri) {
    errors.push("Database URI is required");
  }

  // Validate the nonce registry path (the registry itself refuses a relative one too)
  if (typeof config.usedNonceRegistryPath !== "string" || !path.isAbsolute(config.usedNonceRegistryPath)) {
    errors.push(
      `USED_NONCE_REGISTRY_PATH must be an absolute path to the used-nonce registry file, got ${JSON.stringify(config.usedNonceRegistryPath)}`
    );
  }

  // Validate VTXO
  if (config.mode !== "development" && !config.vtxo.serverPublicKey) {
    errors.push("VTXO_SERVER_PUBKEY is required in non-development mode");
  }

  return errors;
}

/**
 * Loads, normalizes and validates configuration. Returns the normalized
 * configuration: the values the security checks ran on.
 */
export function loadConfig(): SystemConfig {
  const raw = loadConfigFromEnv();
  const errors = validateConfig(raw);

  if (errors.length > 0) {
    throw new Error(`Configuration errors:\n${errors.join("\n")}`);
  }

  const config = normalizeConfig(raw);

  // Startup log (C3): surface the key custody and the configured trusted
  // oracle/ASP key so operators can verify what the verifier will pin.
  console.log(
    `[config] mode=${config.mode} network=${config.network} keyProvider=${config.keys.provider}`
  );
  console.log(
    `[config] trusted oracle/ASP key (vtxo.serverPublicKey): ${
      config.vtxo.serverPublicKey || "(unset)"
    }`
  );

  return config;
}
