/**
 * Round-16 regression tests: the registry init flag is one-shot (F5), and the
 * refusal for an interrupted first start names the flag (F7).
 *
 *  R16-F5-1  the first start leaves a marker next to the registry
 *  R16-F5-2  with the flag still set, a registry and its anchor both deleted are
 *            refused, and nothing is created
 *  R16-F5-3  with the flag still set, a registry deleted from an empty history is
 *            refused
 *  R16-F5-4  a registry that predates the marker gets one on its next start, so
 *            the same loss is then refused
 *  R16-F5-5  a restart without the flag keeps the history and the marker
 *  R16-F7-1  an interrupted first start (anchor, no registry) is refused without
 *            the flag with a message that names the flag, not a moved registry
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { NonceRegistryLockError, UsedNonceRegistry } from "../src/attestation/used-nonce-registry";

const DIGEST = "ab".repeat(32);

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

const anchorOf = (registryPath: string): string => `${registryPath}.anchor`;
const lockOf = (registryPath: string): string => `${registryPath}.lock`;
const markerOf = (registryPath: string): string => `${registryPath}.created`;

function startError(options: { persistPath: string; initialize?: boolean }): Error {
  try {
    new UsedNonceRegistry(options).close();
  } catch (e) {
    return e as Error;
  }
  throw new Error("expected the start to be refused");
}

describe("R16-F5: the init flag creates a registry once", () => {
  it("R16-F5-1: the first start leaves a marker next to the registry", () => {
    const registryPath = path.join(tmpDir("r16-marker-"), "used-nonces.json");

    new UsedNonceRegistry({ persistPath: registryPath, initialize: true }).close();

    expect(fs.existsSync(markerOf(registryPath))).toBe(true);
  });

  it("R16-F5-2: a registry and its anchor both deleted are refused with the flag still set", () => {
    const registryPath = path.join(tmpDir("r16-both-"), "used-nonces.json");
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    first.checkAndRecord(DIGEST, "event-1", DIGEST);
    first.close();
    fs.unlinkSync(registryPath);
    fs.unlinkSync(anchorOf(registryPath));

    const error = startError({ persistPath: registryPath, initialize: true });

    expect(error).toBeInstanceOf(NonceRegistryLockError);
    expect(error.message).toMatch(/restore the registry/);
    expect(error.message).toMatch(/do not re-init/);
    expect(error.message).not.toMatch(/USED_NONCE_REGISTRY_INIT=1/);
    expect(fs.existsSync(registryPath)).toBe(false);
    expect(fs.existsSync(anchorOf(registryPath))).toBe(false);
    expect(fs.existsSync(lockOf(registryPath))).toBe(false);
  });

  it("R16-F5-3: a registry deleted from an empty history is refused with the flag still set", () => {
    const registryPath = path.join(tmpDir("r16-empty-"), "used-nonces.json");
    new UsedNonceRegistry({ persistPath: registryPath, initialize: true }).close();
    fs.unlinkSync(registryPath);

    const error = startError({ persistPath: registryPath, initialize: true });

    expect(error.message).toMatch(/restore the registry/);
    expect(fs.existsSync(registryPath)).toBe(false);
  });

  it("R16-F5-4: a registry that predates the marker gets one, so a later loss is refused", () => {
    const registryPath = path.join(tmpDir("r16-legacy-"), "used-nonces.json");
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    first.checkAndRecord(DIGEST, "event-1", DIGEST);
    first.close();
    fs.unlinkSync(markerOf(registryPath));

    new UsedNonceRegistry({ persistPath: registryPath }).close();
    expect(fs.existsSync(markerOf(registryPath))).toBe(true);

    fs.unlinkSync(registryPath);
    fs.unlinkSync(anchorOf(registryPath));
    const error = startError({ persistPath: registryPath, initialize: true });
    expect(error.message).toMatch(/restore the registry/);
    expect(fs.existsSync(registryPath)).toBe(false);
  });

  it("R16-F5-5: a restart without the flag keeps the history and the marker", () => {
    const registryPath = path.join(tmpDir("r16-restart-"), "used-nonces.json");
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    first.checkAndRecord(DIGEST, "event-1", DIGEST);
    first.close();

    const restarted = new UsedNonceRegistry({ persistPath: registryPath });
    expect(restarted.get(DIGEST)).toEqual({ eventId: "event-1", messageHash: DIGEST });
    restarted.close();

    expect(fs.existsSync(markerOf(registryPath))).toBe(true);
  });
});

describe("R16-F7: an interrupted first start names the flag", () => {
  it("R16-F7-1: an anchor with no registry is refused without the flag, and the message names the flag", () => {
    const registryPath = path.join(tmpDir("r16-interrupted-"), "used-nonces.json");
    new UsedNonceRegistry({ persistPath: registryPath, initialize: true }).close();
    fs.unlinkSync(registryPath);
    fs.rmSync(markerOf(registryPath), { force: true });

    const error = startError({ persistPath: registryPath });

    expect(error.message).toMatch(/interrupted first start/);
    expect(error.message).toMatch(/USED_NONCE_REGISTRY_INIT=1/);
    expect(error.message).not.toMatch(/at another path/);
    expect(fs.existsSync(lockOf(registryPath))).toBe(false);
  });
});
