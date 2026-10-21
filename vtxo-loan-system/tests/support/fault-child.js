/**
 * Fault-injection child for the used-nonce registry (round 5).
 *
 * usage: node fault-child.js <compiledRegistryModule> <registryPath> <faultJSON>
 *
 * faultJSON: a list of {"at": <1-based index of an fs call>, "kind": ...} (a
 *            single object is accepted too). {"trace": true} prints one CALL line
 *            per fs call instead. "at" 0 or an empty list means no fault.
 *
 * Every fs call the registry makes through the `fs` module is counted. At call
 * number `at`:
 *   kill-before - SIGKILL this process before the call runs (a crash between
 *                 two syscalls; no exit hook runs, the lock file stays)
 *   fail-before - throw an errno-style error without running the call
 *   fail-after  - run the call, then throw EIO (for example a directory fsync
 *                 that fails after the rename has already happened)
 *
 * The scenario is fixed: open the registry, then record four nonces, retrying a
 * failed record once. After every step the child reads the on-disk files with
 * the unpatched fs and checks the commit invariants itself.
 *
 * Output (one line each, written with the unpatched fs.writeSync so that a line
 * written before a SIGKILL is not lost):
 *   CALLS <n>                         number of fs calls made in the run
 *   CALL <n> <fs name>                per fs call, only in trace mode
 *   REFUSED <message>                 the registry refused to open
 *   SIGNED <nonce> <eventId> <msg>    checkAndRecord returned: the signature may be released
 *   FAILED <op> <message>             checkAndRecord threw for this attempt
 *   STATE <logEntries> <anchorIndex>  disk state after a step (anchorIndex -1 = empty tip)
 *   FIRED <call> <fs name> <kind>     the injected fault took effect
 *   ERROR <message>                   an error surfaced out of the scenario (close())
 *   VIOLATION <text>                  an invariant broke inside the child
 *   DONE                              the scenario finished
 */
"use strict";

require("./register.js");

const fs = require("fs");

const [, , modulePath, registryPath, faultArg] = process.argv;
const PARSED = JSON.parse(faultArg);
const TRACE = !Array.isArray(PARSED) && PARSED.trace === true;
const FAULTS = (Array.isArray(PARSED) ? PARSED : [PARSED]).filter((f) => f.at > 0);
// Load the module before instrumenting: Node's loader reads the file through fs.
const { UsedNonceRegistry, NonceRegistryLockError } = require(modulePath);

const emit = (line) => realWriteSync(1, `${line}\n`);

// Keep unpatched handles: the child's own reads and writes must not be counted.
const realWriteSync = fs.writeSync;
const realFns = {};
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
for (const name of INSTRUMENTED) {
  realFns[name] = fs[name];
}

let callCount = 0;
function injected(name, kind) {
  const err = new Error(`injected ${kind} in fs.${name}`);
  err.code = name === "writeSync" ? "ENOSPC" : "EIO";
  return err;
}
for (const name of INSTRUMENTED) {
  fs[name] = function instrumented(...args) {
    callCount += 1;
    if (TRACE) {
      emit(`CALL ${callCount} ${name}`);
    }
    const hit = FAULTS.find((f) => f.at === callCount);
    const fault = hit ? hit.kind : null;
    if (fault !== null) {
      emit(`FIRED ${callCount} ${name} ${fault}`);
    }
    if (fault === "kill-before") {
      process.kill(process.pid, "SIGKILL");
    }
    if (fault === "fail-before") {
      throw injected(name, fault);
    }
    const result = realFns[name].apply(fs, args);
    if (fault === "fail-after") {
      throw injected(name, fault);
    }
    return result;
  };
}

function readRaw(file) {
  try {
    return realFns.readFileSync(file, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") {
      return null;
    }
    throw e;
  }
}

/** Disk state: entries, anchored tip, and the anchored index (-1 = empty tip, -2 = unknown) */
function diskState() {
  const logText = readRaw(registryPath);
  const anchorText = readRaw(`${registryPath}.anchor`);
  const entries = logText === null ? [] : JSON.parse(logText).entries;
  if (anchorText === null) {
    return { entries, anchorIndex: -2, anchorMissing: true };
  }
  const tip = JSON.parse(anchorText).tip;
  const anchorIndex = tip === null ? -1 : entries.findIndex((entry) => entry.chain === tip);
  return { entries, anchorIndex, anchorMissing: false };
}

function checkStep(step) {
  const { entries, anchorIndex, anchorMissing } = diskState();
  emit(`STATE ${entries.length} ${anchorIndex}`);
  if (anchorMissing && entries.length > 0) {
    emit(`VIOLATION ${step}: log has records but the anchor is missing`);
  }
  if (!anchorMissing && anchorIndex === -2) {
    emit(`VIOLATION ${step}: anchored tip is not on the log`);
  }
  if (!anchorMissing && anchorIndex !== -2 && entries.length - 1 - anchorIndex > 1) {
    emit(`VIOLATION ${step}: log is ${entries.length - 1 - anchorIndex} entries ahead of the anchor`);
  }
}

const OPS = [
  { nonce: "11", eventId: "e1", message: "aa" },
  { nonce: "22", eventId: "e2", message: "bb" },
  { nonce: "11", eventId: "e1", message: "aa" }, // identical repeat
  { nonce: "33", eventId: "e3", message: "cc" },
];

function main() {
  let registry;
  try {
    registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
  } catch (e) {
    emit(`REFUSED ${e.message}`);
    emit(`CALLS ${callCount}`);
    process.exit(3);
  }
  checkStep("open");

  OPS.forEach((op, index) => {
    const nonceId = op.nonce.repeat(32);
    const messageHash = op.message.repeat(32);
    let signed = false;
    for (let attempt = 1; attempt <= 2 && !signed; attempt += 1) {
      try {
        registry.checkAndRecord(nonceId, op.eventId, messageHash);
        signed = true;
        // Invariants at the moment a signature may be released.
        const { entries, anchorIndex } = diskState();
        const durable = entries.some(
          (entry) =>
            entry.nonceId === nonceId &&
            entry.eventId === op.eventId &&
            entry.messageHash === messageHash
        );
        if (!durable) {
          emit(`VIOLATION signed ${index}: record not durable in the log`);
        }
        if (anchorIndex !== entries.length - 1) {
          emit(`VIOLATION signed ${index}: anchor does not cover the signed record`);
        }
        emit(`SIGNED ${nonceId} ${op.eventId} ${messageHash}`);
      } catch (e) {
        emit(`FAILED ${index} ${String(e.message).replace(/\s+/g, " ")}`);
        if (e instanceof NonceRegistryLockError) {
          break;
        }
      }
      checkStep(`op ${index} attempt ${attempt}`);
    }
  });

  registry.close();
  emit(`CALLS ${callCount}`);
  emit("DONE");
}

try {
  main();
} catch (e) {
  // An error surfaced to the caller (an injected fault in close(), for example).
  emit(`ERROR ${String(e && e.message ? e.message : e).replace(/\s+/g, " ")}`);
  process.exit(4);
}
