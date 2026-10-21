/**
 * Used-Nonce Registry
 *
 * Persists every derived signing nonce that has been used for an attestation
 * and refuses to let the same nonce material be reused.
 *
 * Reusing a BIP-340 nonce k across two different signatures leaks the oracle
 * private key (x = (s1 - s2) / (e1 - e2)). The derivation in
 * attestation-engine.ts binds the eventId into the derivation path, but the
 * derivation itself is deterministic: if it were ever weakened, reset, or
 * collided, this registry is the fail-closed backstop.
 *
 * Policy: a signing nonce k may only ever sign one (eventId, messageHash) pair.
 * The registry identifies k by its public point R (`nonceId`). Reuse for a
 * DIFFERENT eventId - or for a different message under the same eventId - is
 * refused. Identical (eventId, messageHash) may be signed again: the signature is
 * then identical and reveals nothing new.
 *
 * Guarantees, each enforced by the named function:
 *
 * 1. ONE WRITER PER REGISTRY FILE (acquireLock). The registry path is
 *    canonicalized with realpath BEFORE the lock path `<registry>.lock` is
 *    derived, so symlinked and parent-directory spellings of one file share one
 *    lock. The lock is an O_EXCL create taken once, in the constructor, and held
 *    through an open file descriptor until close(). A second instance - in this
 *    process or another - fails at construction. Before every write the lock is
 *    re-verified by inode identity (assertLockHeld: fstat of the held descriptor
 *    against lstat of the lock path); the descriptor is kept open so that the
 *    inode number cannot be recycled while this instance holds it.
 *
 * 2. NO AUTOMATIC TAKEOVER. This code never reclaims an existing lock, whatever
 *    it contains (pid, hostname, age). Node exposes no kernel file lock
 *    (flock/fcntl) in its standard library, and pid, hostname or mtime checks
 *    cannot prove that a writer is dead, so any automatic reclaim races with a
 *    live writer. A lock left by a crashed process therefore blocks startup until
 *    an operator confirms that no process uses the registry and removes the lock
 *    file. The error message says exactly that. Recovery does not lose history:
 *    once the lock is cleared, the anchor (guarantee 4) is checked on every start.
 *
 * 3. ALIASING IS REFUSED (assertSingleLink). The registry must be a regular file
 *    with exactly one hard link. A second hard link would give the other name a
 *    stale copy and a second, independent lock path. Checked on load and again
 *    before each commit. A symlink that resolves to the registry is handled by
 *    guarantee 1.
 *
 * 4. HISTORY IS A CHAINED LOG WITH AN ANCHOR (readVerifiedLog, load, save). Records
 *    are appended to a digest chain: chain[i] = sha256(chain[i-1] || sha256(nonceId
 *    || eventId || messageHash)). The anchor file `<registry>.anchor` records the
 *    chain tip last committed. On start, the anchor must equal the tip of the
 *    verified log, or be exactly one entry behind it. One entry behind means the
 *    process stopped after committing the log and before updating the anchor; that
 *    entry is accepted and the anchor is advanced. Two or more entries ahead of the
 *    anchor is refused, because no crash can produce it. The anchor is caught up
 *    before the next log commit, so a failed anchor write cannot let the log run
 *    ahead in the same process either. A log that is shorter than the anchor, or
 *    diverges from it, is refused. A registry whose anchor is missing while the log
 *    has records is also refused. Both files are read through one descriptor
 *    opened with O_NOFOLLOW, and must be regular single-link files.
 *
 * 5. DURABLE COMMITS (commitFile). The log is committed by writing a
 *    temporary file, fsyncing it, renaming it over the registry, and fsyncing the
 *    directory. A nonce is never signed unless save() returned normally, which
 *    requires the log rename and the anchor rename to have both completed and
 *    their directory fsyncs to have succeeded. The rename is the point where the
 *    in-memory state records the new log tip (the file is then on disk, even if
 *    the directory fsync that follows fails). The anchor is marked stale at that
 *    point, and it is caught up before any further log commit. A record that a
 *    failed commit left pending is committed before a new record is added, so each
 *    log commit writes at most one entry. So after any failed commit the log is at
 *    most one entry ahead of the anchor, and a retry of a recorded nonce re-commits
 *    the anchor before it answers.
 *
 * 9. CREATION IS EXPLICIT AND ONE-SHOT (load, missingRegistryError,
 *    lostRegistryError). The registry, its anchor and the registry directory are
 *    created only with the `initialize` option (USED_NONCE_REGISTRY_INIT=1). Without
 *    it a missing registry refuses to start, so moving the configured path to an
 *    empty location cannot silently abandon the old history. With it, a registry is
 *    created only when there is no history yet, and an existing registry or anchor
 *    is never emptied or replaced. The first creation then writes a marker,
 *    `<registry>.created`, after the registry, and every later start that finds the
 *    registry writes it if it is missing. A registry that is missing while its
 *    marker exists is refused even with `initialize`: the history was lost, and a
 *    flag left set from the first start must not start a fresh one.
 *
 * LIMITS (not enforced here):
 *  - The anchor is unkeyed. Whoever can write the registry directory can rewrite
 *    the log and the anchor together, or delete both, and reset the history. The
 *    anchor only detects truncation that leaves it in place. Mitigation is
 *    operational: restrict the directory to the signer, and back up the anchor.
 *  - The anchor is written after the log, so a crash between the two leaves an
 *    anchor one commit behind. Until the next start advances it, truncating
 *    exactly that last commit is indistinguishable from a crash. This needs
 *    write access to the registry directory, which the limit above already
 *    covers.
 *  - Durability relies on POSIX rename and directory fsync semantics. Platforms
 *    where the directory cannot be fsynced cannot host a registry.
 *  - Upgrading from a version with no anchor file: the start is refused. The
 *    error message gives the anchor format to create by hand from the log tip.
 *  - The marker of guarantee 9 is unkeyed like the anchor. Whoever can delete the
 *    registry directory can delete the marker with the rest; the marker only stops a
 *    leftover init flag from starting a fresh history after an ordinary deletion.
 *
 * 6. NO IN-MEMORY-ONLY MODE OUTSIDE DEVELOPMENT. `persistPath: null` is only
 *    accepted with an explicit `allowInMemory: true` opt-in (the attestation
 *    engine only grants it in development mode on non-mainnet networks).
 *
 * 7. THE LOCK IS RELEASED ON EVERY CLEAN EXIT (installShutdownHooks). The lock is
 *    removed by close(), by process 'exit', and by SIGINT/SIGTERM when this module
 *    is the only listener for that signal (the handler then re-raises the signal
 *    with default disposition). Releasing is safe at those points because every
 *    commit is synchronous: when a hook runs, nothing is half-committed and no
 *    further signature can be produced by this process. A process that is
 *    SIGKILLed, OOM-killed or power-cut keeps its lock (guarantee 2).
 *
 * 8. NO SECRET IN THE LOG. `nonceId` is the public nonce point R that the oracle
 *    announces for an (event, index). The registry must never receive the base
 *    point P of the derived nonce key: the signing nonce is k = oracleKey +
 *    deriveNonceTweak(P, eventId), so P and one published signature reveal the
 *    oracle key (see deriveSigningNonce in attestation-engine.ts). Logs in format
 *    version 2, which stored P, are refused at startup. Their records cannot be
 *    migrated, because the registry does not hold the oracle key to recompute R,
 *    and any published attestation for those events already exposes the oracle
 *    key.
 *
 * NOT ENFORCED:
 *  - Network filesystems (NFS, SMB, FUSE-remote) are unsupported. O_EXCL
 *    exclusivity, rename atomicity and directory fsync are not guaranteed across
 *    clients there, so two hosts can both acquire the lock.
 *  - Keyed anchor (declined). Keying the anchor with an HMAC would stop forging a
 *    new history, but it would have to use a secret held beside the log, so
 *    whoever can read it can also forge it. It cannot stop rollback to an older
 *    consistent snapshot of the log and anchor together. Only an external
 *    monotonic counter can, and this module does not have one.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { isPrintableAsciiId } from "../crypto/tagged-hash";

/**
 * Version of the persisted log format. Version 2 stored the secret-derived base
 * nonce point; version 3 stores the public nonce point (see guarantee 8).
 */
const LOG_FORMAT_VERSION = 3;
/** Version of the anchor file format */
const ANCHOR_FORMAT_VERSION = 1;
/** Chain seed of the append-only log (the "previous chain" of entry 0) */
const GENESIS_DIGEST = "0".repeat(64);
const HEX_DIGEST = /^[0-9a-f]{64}$/;

/** A recorded nonce usage */
export interface NonceRecord {
  /** Event the nonce was used for */
  eventId: string;
  /** Hex-encoded 32-byte digest that was signed */
  messageHash: string;
}

/** Thrown when a derived nonce is about to be reused */
export class NonceReuseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NonceReuseError";
  }
}

/**
 * Thrown when the registry cannot guarantee single-writer access or the
 * integrity of its history. Always fatal: the caller must not sign.
 */
export class NonceRegistryLockError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NonceRegistryLockError";
  }
}

/** A single append-only log entry */
interface LogEntry {
  /** Hex x-only public nonce point R of the signing nonce (never the base point) */
  nonceId: string;
  /** Event the nonce was used for */
  eventId: string;
  /** Hex-encoded 32-byte digest that was signed */
  messageHash: string;
  /** Hex sha256(previous chain || sha256(nonceId || eventId || messageHash)) */
  chain: string;
}

interface PersistedShape {
  version: number;
  entries: LogEntry[];
}

interface AnchorShape {
  version: number;
  /** Chain tip last committed; null = the empty history */
  tip: string | null;
}

/** The single-writer lock held by this instance. The open descriptor pins the inode. */
interface HeldLock {
  readonly lockPath: string;
  readonly fd: number;
  readonly dev: bigint;
  readonly ino: bigint;
}

export interface UsedNonceRegistryOptions {
  /**
   * Absolute path of the JSON file to persist to. Required: a default or relative
   * path would be resolved against the working directory, so a restart from
   * another directory would open an empty registry. Pass null only together with
   * allowInMemory.
   */
  persistPath: string | null;
  /**
   * Explicit opt-in for in-memory-only operation (`persistPath: null`).
   * Refused otherwise: a restart of an in-memory registry forgets every
   * used nonce, which is exactly the nonce-reuse condition. Only the
   * development-mode attestation engine sets this.
   */
  allowInMemory?: boolean;
  /**
   * Creates an empty registry (and its anchor) when none exists at persistPath.
   * This is the first start of a signer (USED_NONCE_REGISTRY_INIT=1), not a
   * default: a missing registry refuses to start without it. It never empties or
   * replaces an existing registry; with a registry or an anchor present it changes
   * nothing.
   */
  initialize?: boolean;
}

/**
 * Registry of used signing nonces.
 */
export class UsedNonceRegistry {
  private readonly entries: Map<string, NonceRecord> = new Map();
  /** Append-only persisted log (same order as insertion) */
  private readonly log: LogEntry[] = [];
  /** Canonical (realpath) registry path; null in in-memory mode */
  private readonly registryPath: string | null;
  private readonly anchorPath: string | null;
  private readonly markerPath: string | null;
  private lock: HeldLock | null = null;
  /** True while in-memory records may not yet be durably committed */
  private uncommitted = false;
  /** Chain tip of the log last committed to disk (what the anchor must record) */
  private committedTip: string | null = null;
  /** True while the anchor on disk lags the committed log */
  private anchorStale = false;

  constructor(options: UsedNonceRegistryOptions) {
    const requested = options.persistPath;
    if (requested === undefined) {
      throw new NonceRegistryLockError(
        "UsedNonceRegistry: persistPath is required (the registry file, or null for in-memory " +
          "operation). A default path would depend on the working directory."
      );
    }

    if (requested === null) {
      if (options.allowInMemory !== true) {
        throw new NonceRegistryLockError(
          "UsedNonceRegistry: in-memory-only operation (persistPath: null) is refused outside " +
            "development: a restart forgets every used nonce and the deterministic derivation " +
            "would then sign twice with the same k, leaking the oracle key. Pass a persistent " +
            "path, or explicitly opt in with allowInMemory in development."
        );
      }
      this.registryPath = null;
      this.anchorPath = null;
      this.markerPath = null;
      return;
    }

    const initialize = options.initialize === true;
    try {
      this.registryPath = canonicalRegistryPath(requested, initialize);
      this.anchorPath = `${this.registryPath}.anchor`;
      this.markerPath = `${this.registryPath}.created`;
      // Single acquisition point for the writer lock.
      this.lock = acquireLock(this.registryPath);
    } catch (e) {
      throw startupError(requested, e);
    }
    heldInstances.add(this);
    installShutdownHooks();
    try {
      this.load(initialize);
      // load() leaves the in-memory log equal to the verified on-disk log.
      this.committedTip = this.tip();
    } catch (e) {
      // Nothing was committed by a failed start (the anchor is only ever
      // advanced after successful verification), so releasing the lock cannot
      // launder tampered history into service.
      try {
        this.releaseLock();
      } catch {
        // the startup error below is the one to report
      }
      throw startupError(this.registryPath!, e);
    }
  }

  /**
   * Checks that the nonce is unused (or was used for exactly the same
   * eventId + message) and records it durably. Throws NonceReuseError
   * otherwise, and throws if the record cannot be committed. The caller must
   * not sign unless this returns normally.
   *
   * @param nonceId - Hex x-only public nonce point R = k*G of the signing nonce (public, never P)
   * @param eventId - Event being signed
   * @param messageHash - Hex digest being signed
   */
  checkAndRecord(nonceId: string, eventId: string, messageHash: string): void {
    if (!HEX_DIGEST.test(nonceId) || !HEX_DIGEST.test(messageHash)) {
      throw new Error(
        "UsedNonceRegistry: nonceId and messageHash must be 32-byte lowercase hex strings"
      );
    }
    if (!isPrintableAsciiId(eventId)) {
      throw new Error("UsedNonceRegistry: eventId must be 1 to 255 printable ASCII characters");
    }
    const existing = this.entries.get(nonceId);
    if (existing) {
      if (existing.eventId !== eventId) {
        throw new NonceReuseError(
          `Refusing to sign: derived nonce ${nonceId} was already used for event ` +
            `"${existing.eventId}" and cannot be reused for event "${eventId}"`
        );
      }
      if (existing.messageHash !== messageHash) {
        throw new NonceReuseError(
          `Refusing to sign: derived nonce ${nonceId} for event "${eventId}" was ` +
            `already used to sign a different message (nonce reuse across messages ` +
            `would leak the oracle key)`
        );
      }
    }
    // Commit whatever an earlier failed commit left pending (a no-op when nothing
    // is pending). A new record is only added to a fully committed log, so each
    // commit writes at most one entry. Otherwise one commit could write several
    // entries, and if its anchor write then failed, the log would be two entries
    // ahead of the anchor and the next start would refuse it.
    this.save();
    if (existing) {
      // Identical (eventId, message): the record is durable now, so re-signing is safe.
      return;
    }

    const previousChain = this.log.length > 0 ? this.log[this.log.length - 1]!.chain : "";
    const entry: LogEntry = { nonceId, eventId, messageHash, chain: "" };
    entry.chain = chainDigest(previousChain, entry);
    this.entries.set(nonceId, { eventId, messageHash });
    this.log.push(entry);
    this.uncommitted = true;
    this.save();
  }

  /** Returns the record for a nonce id, if any */
  get(nonceId: string): NonceRecord | undefined {
    return this.entries.get(nonceId);
  }

  /** Number of registered nonces */
  get size(): number {
    return this.entries.size;
  }

  /**
   * Releases the single-writer lock by removing the lock file. The history
   * and its anchor stay on disk. Throws if the lock was already lost (the lock
   * file was removed or replaced by someone else), because the caller has then
   * been operating without exclusive access.
   */
  close(): void {
    if (this.registryPath === null || this.lock === null) {
      return;
    }
    if (!this.releaseLock()) {
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: the single-writer lock on ${this.registryPath} was removed or ` +
          `replaced while this instance held it; the lock was not removed.`
      );
    }
  }

  /** Chain tip of the in-memory log (null = empty history) */
  private tip(): string | null {
    return this.log.length > 0 ? this.log[this.log.length - 1]!.chain : null;
  }

  /**
   * Confirms that this instance still holds the single-writer lock. Throws
   * before any write if the lock was removed or replaced.
   */
  private assertLockHeld(): void {
    const lock = this.lock;
    if (lock === null || !isSameFile(lock.lockPath, lock.dev, lock.ino)) {
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: lost the single-writer lock on ${this.registryPath} (the lock ` +
          `file was removed or replaced, or the lock was released); refusing to persist ` +
          `nonce state.`
      );
    }
  }

  /**
   * Releases the lock: closes the descriptor, and removes the lock file only
   * if it is still the file this instance created. Returns false if the lock
   * had been lost (the file was left alone).
   */
  private releaseLock(): boolean {
    const lock = this.lock;
    if (lock === null) {
      return true;
    }
    this.lock = null;
    heldInstances.delete(this);
    const stillHeld = isSameFile(lock.lockPath, lock.dev, lock.ino);
    fs.closeSync(lock.fd);
    if (stillHeld) {
      fs.unlinkSync(lock.lockPath);
    }
    return stillHeld;
  }

  // ------------------------------------------------------------------
  // Startup
  // ------------------------------------------------------------------

  /**
   * Verifies the stored history against the anchor, and adopts a strict
   * extension of the anchor (see guarantee 4 in the module comment).
   */
  private load(initialize: boolean): void {
    const registry = this.registryPath!;
    const anchor = readAnchor(this.anchorPath!);
    const logText = readSingleLinkFile(registry);

    if (logText === null) {
      if (anchor !== null && anchor.tip !== null) {
        throw new NonceRegistryLockError(
          `UsedNonceRegistry: ${registry} is missing but its history anchor records tip ` +
            `${anchor.tip}. The used-nonce history was deleted; refusing to start (a fresh ` +
            `registry would reuse nonces and leak the oracle key).`
        );
      }
      if (lstatOrNull(this.markerPath!) !== null) {
        throw lostRegistryError(registry, this.markerPath!);
      }
      if (!initialize) {
        throw anchor === null
          ? missingRegistryError(registry)
          : interruptedStartError(registry, this.anchorPath!);
      }
      // The first start, or one that stopped after creating the anchor. The anchor
      // is written first, so a registry never exists without its anchor, and the
      // marker last, so an interrupted start leaves no marker behind.
      if (anchor === null) {
        this.commitFile(this.anchorPath!, anchorBody(null));
      }
      this.commitFile(registry, logBody([]));
      this.ensureMarker();
      return;
    }

    for (const entry of parseVerifiedLog(logText, registry)) {
      this.entries.set(entry.nonceId, { eventId: entry.eventId, messageHash: entry.messageHash });
      this.log.push(entry);
    }

    if (anchor === null) {
      const tipHint = this.log.length > 0 ? '"<chain of the last entry>"' : "null";
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: ${registry} exists but its history anchor ${this.anchorPath} is ` +
          `missing. Refusing to start: the anchor is what detects truncation. If this registry ` +
          `predates the anchor file, create ${this.anchorPath} containing ` +
          `{"version": ${ANCHOR_FORMAT_VERSION}, "tip": ${tipHint}} after verifying the log, ` +
          `then restart. Otherwise restore the anchor from backup.`
      );
    }

    const tipIndex =
      anchor.tip === null ? -1 : this.log.findIndex((entry) => entry.chain === anchor.tip);
    if (anchor.tip !== null && tipIndex === -1) {
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: ${registry} does not extend the anchored history tip ` +
          `${anchor.tip}: the used-nonce history was truncated, rewritten or reset. ` +
          `Refusing to continue (nonce reuse would leak the oracle key).`
      );
    }
    if (tipIndex < this.log.length - 2) {
      // The anchor is written after every log commit, so a crash leaves it at most
      // one entry behind. Two or more entries ahead is not a crash: refuse.
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: ${registry} is more than one entry ahead of its history anchor ` +
          `${this.anchorPath}. Refusing to adopt it: the anchor is only one commit behind after ` +
          `a crash, so this log was extended or the anchor was rolled back. Restore the ` +
          `matching anchor from backup, then restart.`
      );
    }
    if (tipIndex < this.log.length - 1) {
      // A crash after the log commit and before the anchor update: the log is
      // exactly one entry past the anchored history. Accept it and advance the anchor.
      this.commitFile(this.anchorPath!, anchorBody(this.tip()));
    }
    this.ensureMarker();
  }

  // ------------------------------------------------------------------
  // Persistence
  // ------------------------------------------------------------------

  /**
   * Commits the log, then the anchor. The log commit (the rename) is the
   * commit point for the nonce records. The anchor is the separate recovery
   * record described in guarantee 4. Both steps re-verify the lock first.
   */
  private save(): void {
    if (this.registryPath === null) {
      this.uncommitted = false;
      return;
    }

    // Catch the anchor up before the log may move again, so the log never runs
    // more than one commit ahead of the anchor, even if anchor writes keep failing.
    if (this.anchorStale) {
      this.commitAnchor();
    }
    if (this.uncommitted) {
      this.commitFile(this.registryPath, logBody(this.log), () => {
        // The rename is the commit point. If the directory fsync below fails,
        // the new log is still on disk, so the anchor must be treated as stale.
        this.uncommitted = false;
        this.committedTip = this.tip();
        this.anchorStale = true;
      });
    }
    if (this.anchorStale) {
      this.commitAnchor();
    }
  }

  /** Writes the anchor for the last committed log tip */
  private commitAnchor(): void {
    this.commitFile(this.anchorPath!, anchorBody(this.committedTip));
    this.anchorStale = false;
  }

  /** Records that a registry was created at this path, if the marker is not there yet */
  private ensureMarker(): void {
    if (lstatOrNull(this.markerPath!) === null) {
      this.commitFile(this.markerPath!, Buffer.from("a registry was created at this path\n", "utf8"));
    }
  }

  /**
   * The one durable write of this module (the log and the anchor both use it).
   * Before the temp file is written and again before the rename, this instance
   * re-verifies the lock and that the target is a single-link regular file.
   * `onRenamed` runs right after the rename, before the directory fsync, so a
   * caller can record that the new file is in place even if the fsync throws.
   */
  private commitFile(target: string, body: Buffer, onRenamed: () => void = () => {}): void {
    const verify = (): void => {
      this.assertLockHeld();
      assertSingleLink(target);
    };
    verify();
    const tmp = `${target}.tmp`;
    // Leftover of an interrupted write. Only the lock holder writes here.
    if (lstatOrNull(tmp) !== null) {
      fs.unlinkSync(tmp);
    }

    const fd = fs.openSync(
      tmp,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
      0o600
    );
    try {
      writeAll(fd, body);
      fs.fsyncSync(fd);
      verify();
      fs.renameSync(tmp, target);
      onRenamed();
    } catch (e) {
      fs.closeSync(fd);
      if (lstatOrNull(tmp) !== null) {
        fs.unlinkSync(tmp);
      }
      throw e;
    }
    fs.closeSync(fd);
    fsyncDirectory(path.dirname(target));
  }
}

// ----------------------------------------------------------------------
// Module-level helpers
// ----------------------------------------------------------------------

/** Digest chain: sha256(previous chain || sha256(record fields)) */
function chainDigest(
  previousChain: string,
  entry: Pick<LogEntry, "nonceId" | "eventId" | "messageHash">
): string {
  const previous = previousChain === "" ? GENESIS_DIGEST : previousChain;
  const record = crypto
    .createHash("sha256")
    .update(`${entry.nonceId}\n${entry.eventId}\n${entry.messageHash}`, "utf8")
    .digest("hex");
  return crypto.createHash("sha256").update(previous + record, "utf8").digest("hex");
}

/**
 * The one place the registry path is resolved. Refuses a relative path and, unless
 * initialize is set, a missing parent directory; with initialize it creates the
 * parent. It resolves the path to its canonical form. Every spelling of one file
 * (symlinks, `..`, `.`) maps to the same string, so it yields one lock.
 */
function canonicalRegistryPath(requested: string, initialize: boolean): string {
  if (!path.isAbsolute(requested)) {
    throw new NonceRegistryLockError(
      `UsedNonceRegistry: persistPath must be an absolute path, got ${JSON.stringify(requested)}. ` +
        "A relative path is resolved against the working directory, so a restart from another " +
        "directory would open an empty registry and could re-sign a nonce."
    );
  }
  const absolute = path.resolve(requested);
  if (!initialize && lstatOrNull(path.dirname(absolute)) === null) {
    throw missingRegistryError(absolute);
  }
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  try {
    return fs.realpathSync.native(absolute);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: cannot resolve ${absolute}: ${(e as Error).message}`
      );
    }
  }
  // The file does not exist yet. A dangling symlink also reports ENOENT, and
  // must not be "created" through its target.
  if (lstatOrNull(absolute) !== null) {
    throw new NonceRegistryLockError(
      `UsedNonceRegistry: ${absolute} is a dangling symlink; refusing to create its target`
    );
  }
  return path.join(fs.realpathSync.native(path.dirname(absolute)), path.basename(absolute));
}

/** Instances that currently hold a lock in this process */
const heldInstances = new Set<UsedNonceRegistry>();
let shutdownHooksInstalled = false;

/** Releases every lock this process holds (synchronous; safe in exit handlers) */
function releaseAllHeld(): void {
  for (const instance of [...heldInstances]) {
    try {
      instance.close();
    } catch {
      // the lock was already lost; nothing to release
    }
  }
}

/**
 * Guarantee 7: release on clean exit. A SIGINT/SIGTERM is handled only when this
 * module is the sole listener: the handler then releases the locks and re-raises
 * the signal with default disposition, so the process terminates right away. When
 * other listeners exist the application owns shutdown and must call close().
 */
function installShutdownHooks(): void {
  if (shutdownHooksInstalled) {
    return;
  }
  shutdownHooksInstalled = true;
  process.on("exit", releaseAllHeld);
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    const onSignal = (): void => {
      if (process.listenerCount(signal) !== 1) {
        return;
      }
      process.removeListener(signal, onSignal);
      releaseAllHeld();
      process.kill(process.pid, signal);
    };
    process.on(signal, onSignal);
  }
}

/**
 * Creates `<registryPath>.lock` exclusively. This is the only place a lock is
 * taken. An existing lock is never reclaimed: the error explains how an
 * operator clears a lock left by a crash.
 */
function acquireLock(registryPath: string): HeldLock {
  const lockPath = `${registryPath}.lock`;
  let fd: number;
  try {
    fd = fs.openSync(lockPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: ${registryPath} is locked: ${lockPath} exists${describeLockHolder(
          lockPath
        )}. Refusing to start: two writers could sign with the same derived nonce and leak ` +
          `the oracle key. Locks are never taken over automatically. A lock is left only by a ` +
          `process that was killed with SIGKILL, ran out of memory, or lost power. To recover: ` +
          `(1) confirm that no signer process is running against this registry (for example ` +
          `\`ps aux | grep -i oracle\` and check the recorded pid); (2) run ` +
          `\`rm -- ${shellQuote(lockPath)}\`; (3) restart. The removal does not touch the history or the ` +
          `anchor, and both are re-verified on restart.`
      );
    }
    throw new NonceRegistryLockError(
      `UsedNonceRegistry: cannot create lock ${lockPath}: ${(e as Error).message}`
    );
  }

  let st: fs.BigIntStats;
  try {
    st = fs.fstatSync(fd, { bigint: true });
    const info = {
      pid: process.pid,
      hostname: os.hostname(),
      acquiredAt: new Date().toISOString(),
    };
    writeAll(fd, Buffer.from(JSON.stringify(info, null, 2), "utf8"));
    fs.fsyncSync(fd);
  } catch (e) {
    // We created this file and never returned the lock: remove it so a failed
    // start does not wedge the registry.
    fs.closeSync(fd);
    try {
      const current = lstatOrNull(lockPath);
      if (current !== null) {
        fs.unlinkSync(lockPath);
      }
    } catch {
      // best-effort; the error below is the one to report
    }
    throw new NonceRegistryLockError(
      `UsedNonceRegistry: cannot initialize lock ${lockPath}: ${(e as Error).message}`
    );
  }

  return { lockPath, fd, dev: st.dev, ino: st.ino };
}

/** Best-effort, informational only: never used for a decision */
function describeLockHolder(lockPath: string): string {
  try {
    const info = JSON.parse(fs.readFileSync(lockPath, "utf8")) as Partial<{
      pid: number;
      hostname: string;
      acquiredAt: string;
    }>;
    return ` (recorded holder: pid ${info.pid} on ${info.hostname} since ${info.acquiredAt})`;
  } catch {
    return "";
  }
}

/** True when `lockPath` is still the regular file with the given identity */
function isSameFile(filePath: string, dev: bigint, ino: bigint): boolean {
  const st = lstatOrNull(filePath);
  return st !== null && st.isFile() && st.dev === dev && st.ino === ino;
}

/** lstat with bigint fields; null when the path does not exist */
function lstatOrNull(filePath: string): fs.BigIntStats | null {
  try {
    return fs.lstatSync(filePath, { bigint: true });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw e;
  }
}

/**
 * The one single-link rule: a nonce-state file must be a regular file with exactly
 * one hard link. Applied to the lstat of a path (before a write) and to the fstat
 * of an open descriptor (before a read).
 */
function assertSingleLinkStat(filePath: string, st: fs.BigIntStats): void {
  if (!st.isFile() || st.nlink !== 1n) {
    throw new NonceRegistryLockError(
      `UsedNonceRegistry: ${filePath} must be a regular file with exactly one hard link ` +
        `(found ${st.isFile() ? `${st.nlink} links` : "a non-regular file"}); refusing to ` +
        `read or persist nonce state through an alias.`
    );
  }
}

/** Single-link check of the file currently at `filePath`, if any */
function assertSingleLink(filePath: string): void {
  const st = lstatOrNull(filePath);
  if (st !== null) {
    assertSingleLinkStat(filePath, st);
  }
}

/**
 * Reads a regular, single-link file through one descriptor opened with
 * O_NOFOLLOW. The type and link count are checked on that descriptor, so the
 * bytes returned are the bytes of the checked file (no lstat-then-read window).
 * Returns null when the file does not exist.
 */
function readSingleLinkFile(filePath: string): string | null {
  let fd: number;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return null;
    }
    if (code === "ELOOP") {
      // O_NOFOLLOW on a symlink. Any other error is a storage error and goes to startupError.
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: ${filePath} is a symbolic link; refusing to read nonce state through a link`
      );
    }
    throw e;
  }
  try {
    assertSingleLinkStat(filePath, fs.fstatSync(fd, { bigint: true }));
    return fs.readFileSync(fd, "utf8");
  } finally {
    fs.closeSync(fd);
  }
}

/** Reads the anchor. null = no anchor file. */
function readAnchor(anchorPath: string): { tip: string | null } | null {
  const text = readSingleLinkFile(anchorPath);
  if (text === null) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new NonceRegistryLockError(
      `UsedNonceRegistry: cannot read history anchor ${anchorPath}: ${(e as Error).message}`
    );
  }
  const shape = parsed as Partial<AnchorShape> | null;
  const validTip =
    shape !== null &&
    typeof shape === "object" &&
    shape.version === ANCHOR_FORMAT_VERSION &&
    (shape.tip === null || (typeof shape.tip === "string" && HEX_DIGEST.test(shape.tip)));
  if (!validTip) {
    throw new NonceRegistryLockError(
      `UsedNonceRegistry: history anchor ${anchorPath} is malformed; refusing to start.`
    );
  }
  return { tip: shape!.tip as string | null };
}

function anchorBody(tip: string | null): Buffer {
  const anchor: AnchorShape = { version: ANCHOR_FORMAT_VERSION, tip };
  return Buffer.from(JSON.stringify(anchor, null, 2), "utf8");
}

function logBody(entries: LogEntry[]): Buffer {
  const payload: PersistedShape = { version: LOG_FORMAT_VERSION, entries };
  return Buffer.from(JSON.stringify(payload, null, 2), "utf8");
}

/**
 * Refusal for a registry that does not exist. A missing registry is an empty
 * history, and an empty history signs nonces again, so it is never created
 * without the explicit initialize option.
 */
function missingRegistryError(registryPath: string): NonceRegistryLockError {
  return new NonceRegistryLockError(
    `UsedNonceRegistry: ${registryPath} does not exist. Refusing to start: a missing registry ` +
      `is an empty history, and an empty history signs nonces again. If this signer has run ` +
      `before, its registry is at another path (the default before the path was required was ` +
      `data/used-nonces.json, relative to the working directory). Move the registry file and ` +
      `its anchor ${registryPath}.anchor together to this path, with these names, then restart. ` +
      `Do not move the registry alone, and do not leave an empty file in its place. If this ` +
      `signer has never had a registry, set USED_NONCE_REGISTRY_INIT=1 for one start, then unset it.`
  );
}

/**
 * Refusal for an anchor with no registry and no recorded history. The first start
 * stopped after it wrote the anchor, and only the init flag finishes that start.
 */
function interruptedStartError(registryPath: string, anchorPath: string): NonceRegistryLockError {
  return new NonceRegistryLockError(
    `UsedNonceRegistry: ${registryPath} does not exist, but ${anchorPath} does and records no ` +
      `history. This is an interrupted first start. Set USED_NONCE_REGISTRY_INIT=1 for one start ` +
      `to create the registry, then unset it. If the registry was moved to another path, move it ` +
      `back to this path, with its anchor, instead.`
  );
}

/**
 * Refusal for a registry that is missing while its marker says one was created here.
 * The history was lost, so the init flag does not apply: a fresh registry would sign
 * nonces again.
 */
function lostRegistryError(registryPath: string, markerPath: string): NonceRegistryLockError {
  return new NonceRegistryLockError(
    `UsedNonceRegistry: ${registryPath} is missing, but ${markerPath} shows that a registry was ` +
      `created at this path. The used-nonce history was deleted. To recover, restore the registry ` +
      `from backup, with its anchor, then restart; do not re-init. A fresh registry would reuse ` +
      `nonces and leak the oracle key, so the init flag does not help here.`
  );
}

/**
 * Parses the registry and verifies every link of the digest chain. Refuses
 * truncation, reordering, rewriting, malformed entries, and duplicate nonces
 * (a valid log never contains two records for one nonce).
 */
function parseVerifiedLog(text: string, registryPath: string): LogEntry[] {
  let parsed: PersistedShape;
  try {
    parsed = JSON.parse(text) as PersistedShape;
  } catch (e) {
    throw new NonceRegistryLockError(
      `UsedNonceRegistry: cannot read ${registryPath}: ${(e as Error).message}`
    );
  }
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.entries)) {
    throw new NonceRegistryLockError(
      `UsedNonceRegistry: ${registryPath} has a malformed payload; refusing to continue.`
    );
  }
  if (parsed.version === 2) {
    throw new NonceRegistryLockError(
      `UsedNonceRegistry: ${registryPath} is a format-version-2 registry. Version 2 stored the ` +
        `secret-derived base nonce point, so with any published attestation for these events ` +
        `the oracle private key can be computed. Refusing to start. Do NOT restart with the ` +
        `same oracle key: a fresh registry under that key would sign nonces already used, ` +
        `which leaks the key. First check whether this file came from the pre-R5 build: a ` +
        `file written by an attacker is refused the same way. If any attestation was published ` +
        `for an event recorded here, the oracle key is compromised: rotate it. Only after that, ` +
        `move this registry and its anchor aside, and keep both until the rotation is complete ` +
        `(they contain base points).`
    );
  }
  if (parsed.version !== LOG_FORMAT_VERSION) {
    throw new NonceRegistryLockError(
      `UsedNonceRegistry: ${registryPath} has unsupported format version ${String(parsed.version)}; ` +
        `refusing to continue.`
    );
  }

  const verified: LogEntry[] = [];
  const seen = new Set<string>();
  let previous = "";
  for (const entry of parsed.entries) {
    if (
      !entry ||
      typeof entry.nonceId !== "string" ||
      typeof entry.eventId !== "string" ||
      typeof entry.messageHash !== "string" ||
      typeof entry.chain !== "string" ||
      !HEX_DIGEST.test(entry.nonceId) ||
      !HEX_DIGEST.test(entry.messageHash) ||
      !isPrintableAsciiId(entry.eventId)
    ) {
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: ${registryPath} contains a malformed entry; refusing to continue.`
      );
    }
    if (chainDigest(previous, entry) !== entry.chain) {
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: ${registryPath} failed its digest-chain check at nonce ` +
          `${entry.nonceId}: the used-nonce history was truncated, reordered or rewritten. ` +
          `Refusing to continue (nonce reuse would leak the oracle key).`
      );
    }
    if (seen.has(entry.nonceId)) {
      throw new NonceRegistryLockError(
        `UsedNonceRegistry: ${registryPath} records nonce ${entry.nonceId} twice; ` +
          `refusing to continue.`
      );
    }
    seen.add(entry.nonceId);
    verified.push({ ...entry });
    previous = entry.chain;
  }
  return verified;
}

/**
 * Single-quotes a path for a POSIX shell. A single quote inside the path is written
 * as '\'' (close the quote, an escaped quote, reopen), so the hint is copy-paste safe.
 */
function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/**
 * The one startup boundary: every failure of the constructor leaves as a
 * NonceRegistryLockError with an operator message. A raw storage error (EIO,
 * ENOSPC, ...) is wrapped, so a restart never refuses with a bare errno.
 */
function startupError(registryPath: string, error: unknown): NonceRegistryLockError {
  if (error instanceof NonceRegistryLockError) {
    return error;
  }
  const reason = error instanceof Error ? error.message : String(error);
  return new NonceRegistryLockError(
    `UsedNonceRegistry: startup could not complete for ${registryPath} (${reason}). Nothing ` +
      `was signed by this start. Fix the storage error, then restart.`
  );
}

/** Writes every byte, looping over short writes */
function writeAll(fd: number, body: Buffer): void {
  let offset = 0;
  while (offset < body.length) {
    offset += fs.writeSync(fd, body, offset, body.length - offset, null);
  }
}

/** fsyncs a directory so that a rename inside it is durable */
function fsyncDirectory(dir: string): void {
  const fd = fs.openSync(dir, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}
