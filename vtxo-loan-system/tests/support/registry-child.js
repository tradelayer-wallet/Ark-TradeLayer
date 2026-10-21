/**
 * Child process helper for cross-process used-nonce registry probes.
 *
 * usage: node registry-child.js <registryPath> <mode>
 *
 * Modes:
 *   record  - open the registry, record a nonce, then SIGKILL itself: no exit
 *             handler runs, so the lockfile remains (a true crash)
 *   hold    - open the registry, record a nonce, announce HELD, stay alive
 *   exit    - record a nonce, announce RECORDED, then process.exit(0) without close()
 *             (a clean exit: the lockfile must be released)
 *   open    - open the registry and announce OPENED (fails loudly on refusal)
 *   race    - wait until the absolute time <startAtMs> (argv[4]), then open the
 *             registry and record the SAME nonce with event "race-<pid>"; announce
 *             ACQUIRED and hold for 1.5s, or announce REFUSED (exit 3)
 */
"use strict";

require("./register.js");

const {
  UsedNonceRegistry,
  NonceRegistryLockError,
} = require("../../src/attestation/used-nonce-registry");

const [, , registryPath, mode, startAtArg] = process.argv;

try {
  if (mode === "race") {
    const startAt = Number(startAtArg);
    while (Date.now() < startAt) {
      // spin until the shared start time so both racers contend at once
    }
  }

  const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });

  if (mode === "race") {
    registry.checkAndRecord("dd".repeat(32), `race-${process.pid}`, "ee".repeat(32));
    console.log("ACQUIRED");
    setTimeout(() => process.exit(0), 1500);
    return;
  }

  if (mode === "record") {
    registry.checkAndRecord("aa".repeat(32), "event-child", "bb".repeat(32));
    console.log("RECORDED");
    process.kill(process.pid, "SIGKILL"); // true crash: no exit hook, lockfile stays
  }

  if (mode === "hold") {
    registry.checkAndRecord("cc".repeat(32), "event-hold", "dd".repeat(32));
    console.log("HELD");
    setTimeout(() => process.exit(0), 10_000);
    return;
  }

  if (mode === "exit") {
    registry.checkAndRecord("ee".repeat(32), "event-exit", "ff".repeat(32));
    console.log("RECORDED");
    process.exit(0);
  }

  if (mode === "open") {
    console.log("OPENED");
    process.exit(0);
  }

  console.error(`unknown mode: ${mode}`);
  process.exit(2);
} catch (e) {
  if (e instanceof NonceRegistryLockError || (e && e.name === "NonceRegistryLockError")) {
    console.log(`REFUSED: ${e.message}`);
    process.exit(3);
  }
  console.error(String(e && e.stack ? e.stack : e));
  process.exit(4);
}
