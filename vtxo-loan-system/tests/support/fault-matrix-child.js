/**
 * Round-7 fault-matrix child for the used-nonce registry.
 *
 * usage: node fault-matrix-child.js <compiledRegistryModule> <registryPath> <phase> <faultJSON>
 *
 * phase "run":  open, record three consecutive nonces plus one identical repeat,
 *               then close(). Retries a failed record once. Errors from close()
 *               surface as ERROR lines (the exit/release path).
 * phase "open": open and close once, nothing else (a restart).
 *
 * faultJSON: {"at": <1-based fs call index>, "kind": "kill-before" | "fail-before" | "fail-after"}
 *            or {"at": 0} for no fault. Every call through the instrumented fs
 *            functions is counted, including those made by close().
 *
 * Output lines:
 *   CALLS <n>                      fs calls made in this run
 *   FIRED <call> <fs name> <kind>  the injected fault took effect
 *   OPEN_FAILED <name> <message>   the constructor threw
 *   SIGNED <nonce> <eventId> <msg> checkAndRecord returned normally
 *   FAILED <index> <message>       checkAndRecord threw for this attempt
 *   STATE <entries> <anchorIndex>  disk state after a step
 *   VIOLATION <text>               an invariant broke inside the child
 *   ERROR <message>                an error surfaced from close()
 *   OPENED / CLOSED                phase "open" milestones
 *   DONE
 */
"use strict";

require("./register.js");

const fs = require("fs");

const [, , modulePath, registryPath, phase, faultArg] = process.argv;
const FAULT = JSON.parse(faultArg);
// Load the module before instrumenting: the loader reads files through fs.
const { UsedNonceRegistry, NonceRegistryLockError, NonceReuseError } = require(modulePath);

const realWriteSync = fs.writeSync;
const emit = (line) => realWriteSync(1, `${line}\n`);
const flat = (text) => String(text).replace(/\s+/g, " ");

const INSTRUMENTED = [
  "openSync",
  "writeSync",
  "fsyncSync",
  "renameSync",
  "closeSync",
  "unlinkSync",
  "lstatSync",
  "fstatSync",
  "readFileSync",
  "mkdirSync",
];
const realFns = {};
for (const name of INSTRUMENTED) {
  realFns[name] = fs[name];
}
const realNativeRealpath = fs.realpathSync.native;

let callCount = 0;
const faultFor = (name) => {
  callCount += 1;
  if (FAULT.at !== callCount) return null;
  emit(`FIRED ${callCount} ${name} ${FAULT.kind}`);
  return FAULT.kind;
};
const injected = (name) => {
  const err = new Error(`injected fault in fs.${name}`);
  err.code = "EIO";
  return err;
};

for (const name of INSTRUMENTED) {
  fs[name] = function instrumented(...args) {
    const fault = faultFor(name);
    if (fault === "kill-before") process.kill(process.pid, "SIGKILL");
    if (fault === "fail-before") throw injected(name);
    const result = realFns[name].apply(fs, args);
    if (fault === "fail-after") throw injected(name);
    return result;
  };
}
fs.realpathSync.native = function instrumentedRealpath(...args) {
  const fault = faultFor("realpathSync.native");
  if (fault === "kill-before") process.kill(process.pid, "SIGKILL");
  if (fault === "fail-before") throw injected("realpathSync.native");
  const result = realNativeRealpath.apply(fs.realpathSync, args);
  if (fault === "fail-after") throw injected("realpathSync.native");
  return result;
};

function readRaw(file) {
  try {
    return realFns.readFileSync(file, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
}

/** Disk state: entries and the anchored index (-1 = empty tip, -2 = anchor not on the log) */
function diskState() {
  const logText = readRaw(registryPath);
  const anchorText = readRaw(`${registryPath}.anchor`);
  const entries = logText === null ? [] : JSON.parse(logText).entries;
  if (anchorText === null) return { entries, anchorIndex: -3 };
  const tip = JSON.parse(anchorText).tip;
  const anchorIndex = tip === null ? -1 : entries.findIndex((entry) => entry.chain === tip);
  return { entries, anchorIndex: anchorIndex === -1 && tip !== null ? -2 : anchorIndex };
}

function checkStep(step) {
  const { entries, anchorIndex } = diskState();
  emit(`STATE ${entries.length} ${anchorIndex}`);
  if (anchorIndex === -3 && entries.length > 0) {
    emit(`VIOLATION ${step}: log has records but the anchor is missing`);
  } else if (anchorIndex === -2) {
    emit(`VIOLATION ${step}: anchored tip is not on the log`);
  } else if (anchorIndex >= 0 && entries.length - 1 - anchorIndex > 1) {
    emit(`VIOLATION ${step}: log is ${entries.length - 1 - anchorIndex} entries ahead of the anchor`);
  }
}

// Three consecutive records, then an identical repeat of the first (the existing-record path).
const OPS = [
  { nonce: "11", eventId: "e1", message: "aa" },
  { nonce: "22", eventId: "e2", message: "bb" },
  { nonce: "33", eventId: "e3", message: "cc" },
  { nonce: "11", eventId: "e1", message: "aa" },
];

function runPhase() {
  let registry;
  try {
    registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
  } catch (e) {
    emit(`OPEN_FAILED ${e.name} ${flat(e.message)}`);
    emit(`CALLS ${callCount}`);
    process.exit(3);
  }
  checkStep("open");

  OPS.forEach((op, index) => {
    const nonceId = op.nonce.repeat(32);
    const messageHash = op.message.repeat(32);
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      try {
        registry.checkAndRecord(nonceId, op.eventId, messageHash);
        // Invariant at the moment a signature may be released: the record is durable and
        // the anchor covers it.
        const { entries, anchorIndex } = diskState();
        const durable = entries.some(
          (entry) =>
            entry.nonceId === nonceId && entry.eventId === op.eventId && entry.messageHash === messageHash
        );
        if (!durable) emit(`VIOLATION signed ${index}: record not durable in the log`);
        if (anchorIndex !== entries.length - 1) {
          emit(`VIOLATION signed ${index}: anchor does not cover the signed record`);
        }
        emit(`SIGNED ${nonceId} ${op.eventId} ${messageHash}`);
        break;
      } catch (e) {
        emit(`FAILED ${index} ${flat(e.message)}`);
        if (e instanceof NonceRegistryLockError || e instanceof NonceReuseError) break;
      }
      checkStep(`op ${index} attempt ${attempt}`);
    }
    checkStep(`after op ${index}`);
  });

  try {
    registry.close();
  } catch (e) {
    emit(`ERROR ${flat(e.message)}`);
  }
  emit(`CALLS ${callCount}`);
  emit("DONE");
}

function openPhase() {
  let registry;
  try {
    registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
  } catch (e) {
    emit(`OPEN_FAILED ${e.name} ${flat(e.message)}`);
    emit(`CALLS ${callCount}`);
    process.exit(3);
  }
  emit("OPENED");
  try {
    registry.close();
    emit("CLOSED");
  } catch (e) {
    emit(`ERROR ${flat(e.message)}`);
  }
  emit(`CALLS ${callCount}`);
  emit("DONE");
}

if (phase === "run") runPhase();
else if (phase === "open") openPhase();
else {
  emit(`VIOLATION unknown phase ${phase}`);
  process.exit(2);
}
