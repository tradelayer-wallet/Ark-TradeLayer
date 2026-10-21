/**
 * Jest configuration for the vtxo-loan-system behavioral test suite.
 *
 * Notes:
 * - `cfd-js` (pinned in package.json) is unpublished on npm; tests map it to
 *   the standard BIP-340 shim in tests/shims/. This is test-only scaffolding.
 * - ts-jest runs in transpile-only mode: the repository has pre-existing
 *   type errors (see the tsc baseline) and the tests must not depend on them.
 */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/tests"],
  testMatch: ["**/*.test.ts"],
  transform: {
    "^.+\\.ts$": ["ts-jest", { diagnostics: false }],
  },
  moduleNameMapper: {
    "^cfd-js$": "<rootDir>/tests/shims/cfd-js.js",
  },
};
