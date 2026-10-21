/**
 * Round-2 regression tests, configuration (Ark-TradeLayer findings N7, N8).
 *
 *  N7  validateConfig normalizes network and mode itself; unknown values are fatal
 *  N8  API_AUTH_KEY strength is enforced outside development
 */
import {
  DEFAULT_API_AUTH_KEY,
  SystemConfig,
  apiAuthKeyViolation,
  validateConfig,
} from "../src/config/system-config";

function makeConfig(overrides: Partial<SystemConfig> = {}): SystemConfig {
  return {
    network: "testnet",
    mode: "production",
    keys: { provider: "gcp", projectId: "proj", secretId: "secret", allowLocalKeys: false },
    database: { uri: "mongodb://localhost:27017", database: "test" },
    redis: { host: "127.0.0.1", port: 6379 },
    externalData: { priceFeeds: { enabled: ["coingecko"] }, blockchainClients: {} },
    api: {
      publicPort: 3000,
      internalPort: 3001,
      authKey: "strong-random-api-key",
      cors: { enabled: true, origins: ["*"] },
    },
    monitoring: { logLevel: "info" },
    scheduler: { priceCheckInterval: 5, paymentCheckInterval: 2, announcementLookahead: 13 },
    vtxo: { defaultExitDelay: 1008, serverPublicKey: "aabbcc", minContractValue: 10000 },
    usedNonceRegistryPath: "/srv/vtxo/used-nonces.json",
    usedNonceRegistryInit: true,
    ...overrides,
  };
}

describe("N7: validateConfig normalizes network and mode itself", () => {
  it("non-canonical network/mode spellings cannot skip the mainnet-implied checks", () => {
    expect(() =>
      validateConfig(
        makeConfig({
          network: "Mainnet" as any,
          mode: "development",
          keys: { provider: "mock", allowLocalKeys: false },
        })
      )
    ).toThrow(/KEY_PROVIDER=mock/);
    expect(() =>
      validateConfig(
        makeConfig({
          network: "mainnet",
          mode: " Development " as any,
          keys: { provider: "mock", allowLocalKeys: false },
        })
      )
    ).toThrow(/KEY_PROVIDER=mock/);
  });

  it("an unrecognized network or mode is fatal, not a soft error a caller can ignore", () => {
    expect(() => validateConfig(makeConfig({ network: "moonnet" as any }))).toThrow(
      /Unrecognized network/
    );
    expect(() => validateConfig(makeConfig({ mode: "prod" as any }))).toThrow(
      /Unrecognized mode/
    );
  });
});

describe("N8: API_AUTH_KEY strength policy", () => {
  it("whitespace-only, short and placeholder keys are refused outside development", () => {
    for (const key of [" ", "   ", "short-key", "0123456789abcde", DEFAULT_API_AUTH_KEY]) {
      expect(() =>
        validateConfig(makeConfig({ mode: "production", api: { ...makeConfig().api, authKey: key } }))
      ).toThrow(/API_AUTH_KEY/);
    }
    expect(
      validateConfig(
        makeConfig({ mode: "production", api: { ...makeConfig().api, authKey: "0123456789abcdef" } })
      )
    ).toEqual([]);
  });

  it("the policy is one function, and development is not affected by it", () => {
    expect(apiAuthKeyViolation(" ")).toMatch(/at least 16 non-whitespace/);
    expect(apiAuthKeyViolation(DEFAULT_API_AUTH_KEY)).toMatch(/insecure default/);
    expect(apiAuthKeyViolation("0123456789abcdef")).toBeNull();
    expect(() =>
      validateConfig(
        makeConfig({
          mode: "development",
          network: "regtest",
          keys: { provider: "mock", allowLocalKeys: false },
          api: { ...makeConfig().api, authKey: " " },
        })
      )
    ).not.toThrow();
  });
});
