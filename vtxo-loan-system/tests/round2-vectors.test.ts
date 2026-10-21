/**
 * Round-2 regression test, shared vectors (Ark-TradeLayer finding R2).
 *
 * The .ark matcher and the TypeScript signer must agree on the encoding and on
 * what is refused. The vectors document both.
 */
import * as fs from "fs";
import * as path from "path";

import { hashEventId } from "../src/crypto/tagged-hash";

const VECTORS = path.join(__dirname, "vectors", "attestation-vectors.json");

describe("R2: the shared vectors document the encoding and the refusals", () => {
  it("documents lenpfx as a 4-byte big-endian length and carries the empty-eventId refusal", () => {
    const vectors = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
    expect(vectors.$comment).toContain("4-byte big-endian length");
    const refusal = vectors.refusals.find((r: { name: string }) => r.name === "empty eventId");
    expect(refusal).toBeDefined();
    expect(refusal.expect).toBe("refused");
    expect(() => hashEventId(refusal.eventId)).toThrow(/eventId must be a 1..255/);
  });
});
