# tl-ark-dlc (EXPERIMENTAL)

> **Experimental.** Isolated Rust port of the experimental Ark / DLC code in this repository. Not audited, not
> wired to any network, **synthetic keys only**, interfaces may change. Nothing here signs with real keys or
> moves funds. Unresolved questions are listed below and must be decided by people, not by this crate.

Charter task: *Isolate experimental Ark/DLC code and port verified canonical vectors first.* The crate keeps
all stateful cryptography minimal (one `s = k + e*d` computation on library scalar types, every signature
re-verified by the library's BIP-340 verifier before it is returned) and never reimplements a primitive.

## Baseline and inspected sources

* Baseline: `30187bf66ea0f72ca5a2ad2f31c703487a7efb59` (`main`, "init"). Branch `feat/rust-port`.
* Inspected (blob SHAs from `git rev-parse HEAD:<path>`):

| Legacy file | blob |
| --- | --- |
| `vtxo-loan-system/src/attestation/attestation-engine.ts` | `0421e240ca9bccf5e9d7181a2bb23587ec774f62` |
| `vtxo-loan-system/src/crypto/tagged-hash.ts` | `14ae39c706fe4b819fa31dba4bbc6e5a7e11ec84` |
| `vtxo-loan-system/src/config/system-config.ts` | `663655854ec2aada524c325ed349c3ff19fbc695` |
| `tl-vtxo-handshake-optimized/ark-tradelayer-handshake.js` | `45d93f08df2fe12efd61343d7fa4afc2afff82a8` |
| `tl-vtxo-handshake-optimized/tradelayer-dlc-vtxo-validation-v2.js` | `f75e41fbf1083a92abe1cffca561cb4fc7af35ea` |
| `vtxo-loan-system/contracts/CollateralizedLoan.ark` | `ac4c42133bd1d3ad873e84d03124653aeb021d08` |

Also read: `src/keys/key-provider.ts`, `src/storage/schemas.ts`, `src/witness/event-witness.ts`,
`src/crypto/bitcoin-primitives.ts`, `contracts/UnsecuredLoan.ark`, `.env.example`.
The two copies of the handshake under `tl-vtxo-handshake-optimized/` and
`tl-vtxo-handshake-optimized/ark-tradelayer-handshake-complete/` are **byte-identical** (checked with `cmp`, both
files). The validation file `require`s `./arkTradeLayerHandshake.js` (the real file is
`ark-tradelayer-handshake.js`) plus `txUtils`, `property`, `tally`, none of which exist in the repository, so the
validation file cannot be loaded as shipped; it was ported by reading.

## What is ported

| Module | Legacy source | Contents |
| --- | --- | --- |
| `config` | `system-config.ts` | `Config::from_map(&BTreeMap)`: fail-closed, reports every violation, secrets redacted in `Debug`. |
| `storage` | `schemas.ts` | Typed records (`EventAnnouncementRecord`, `AttestationRecord`, `LoanRecord`, `WitnessLogRecord`), `Store` trait, `MemoryStore` with the legacy unique constraints, nonce records, single-writer `WriterToken`. |
| `witness` | `event-witness.ts` | Payment / threshold / time / composite witnesses, integer arithmetic, injected clock and clients. |
| `attestation` | `attestation-engine.ts`, `tagged-hash.ts` | Descriptors, announcements, event-bound attestations, announced-R binding, `Oracle` with persist-before-sign nonce control, `VerifiedOutcome` proof type. |
| `keys` | `key-provider.ts` | `KeyProvider` trait + `SyntheticKeyProvider` (BIP-32 from a label). Real-key providers are not ported. |
| `loan` | `CollateralizedLoan.ark`, schema status enum | Lifecycle state machine and value splits (`repayFull`, `repayPartial`, `liquidate`, `claimDefault`, `emergencyExit`, dispute). |
| `handshake` | `ark-tradelayer-handshake.js`, `tradelayer-dlc-vtxo-validation-v2.js` | Template registry, deposit/exit recognition (real BIP-341 via the `bitcoin` crate), `Bridge` mint/redeem state machine over a `ChainView` trait. |
| `legacy` | all of the above | Byte-exact legacy layouts used **only** to reproduce the committed legacy vectors. |

### Handshake state machine

`Unseen --WrapMint(valid deposit)--> Minted --Redeem(valid user-exit spend)--> Burned`; every other message in every
state is rejected and leaves the state untouched (a deposit can back one mint, one redeem).

### Loan lifecycle (edges are the only transitions; `lean/TlArkDlc/Loan.lean` mirrors them)

`Pending -> Active`; `Active -> Repaid | Defaulted | Liquidated | Disputed | EmergencyExited`;
`Disputed -> Repaid | Defaulted | Liquidated | EmergencyExited`; the four terminal states have no outgoing edge.

## Canonical vectors

* `fixtures/legacy_vectors.json` is produced by **running the real legacy code**: `scripts/compare-legacy.mjs`
  verifies the pinned blob SHAs (CRLF tolerant), copies `tagged-hash.ts`, `attestation-engine.ts` and
  `ark-tradelayer-handshake.js` **unmodified** into a temp tree, shims only what is unavailable offline
  (`@node-lightning/crypto`'s `sha256`, `cfd-js`, the key providers, `txUtils`, a `.ts` extension resolver hook) and
  calls the real functions (`createTaggedHash`, `hashAttestation`, `hashAnnouncement`, `deriveNonceTweak`,
  `serializeAnnouncementData`, `calculateNoncesNeeded`, `attestNumeric` with `signOutcomes` stubbed, `computeTemplateId`,
  `canonicalJSON`, `computeTaprootOutputKey`, `decodeSegwitOutput`, `reconstructTaprootKey`, `compactSize`).
  Requires Node >= 22.15 (`module.registerHooks`) and `--experimental-transform-types`; no `npm install`.
  Rust reproduces every vector byte for byte (`tests/legacy_vectors.rs`).
* **Not derivable from legacy:** actual Schnorr signatures (legacy needs `cfd-js`, a native module; the repository has
  no lockfile) and anything touching the network. Signature behaviour is covered by library verification in tests.
* `fixtures/v1_vectors.json` holds the *new* v1 messages (event-bound attestation digest, announcement digest, v2
  template id). There is no legacy equivalent, so they are derived by an **independent Node implementation**
  (`scripts/v1-vectors.mjs`, Node `crypto` only) and Rust reproduces them (`tests/v1_vectors.rs`).

## Compatibility table

**Preserved contract**

| Item | Where |
| --- | --- |
| BIP-340 tagged hash, `hashAttestation`/`hashAnnouncement`/`deriveNonceTweak` layouts, legacy announcement serialisation, `canonicalJSON`, legacy `computeTemplateId` bytes | `legacy`, `handshake::template_id_legacy` (vectors) |
| Numeric digit decomposition (`abs(v).toString(base).padStart(n)`, sign first) | `attestation::decompose_numeric` (vectors) |
| `calculateNoncesNeeded`, outcome labels `paid/unpaid/hit/miss/triggered/pending/satisfied/unsatisfied` | `attestation`, `witness` |
| Unique `eventId`, `announcementHash`, `attestationId`, `loanId`, nonce `rValue` | `storage::MemoryStore` |
| `repayPartial` arithmetic (`ratio=repaid*1e6/principal`, floor), `emergencyExit` `penalty=collateral/10` | `loan` |
| 6 confirmations, 10,000 sat burn fee tolerance, user-exit leaf role, allowlist `(templateId, aspId)` | `handshake` |
| Time witness boundaries (`before` strict, `after` inclusive, `exact` +-60 s), payment tolerance default 1% | `witness` |

**Repaired defects** (legacy `file:line` -> new behaviour; each has a regression test)

| # | Legacy | New behaviour |
| --- | --- | --- |
| 1 | `tagged-hash.ts:69`, `attestation-engine.ts:331-337`: signed message is `H(outcome)` only, so one attestation verifies for any event/oracle/index with that outcome | v1 message binds oracle key, event id, announcement digest, index, announced R, outcome (tag `TL/ark-dlc/oracle-attestation/v1`). `tests/attestation.rs::messages_are_event_bound_unlike_legacy`, Lean `attestation_for_a_not_valid_for_b` |
| 2 | `attestation-engine.ts:353-387`: `verifyAttestation` never compares the signature's R with `noncePoints` (R binding off-chain only), skips the announcement signature, outcome membership and count | `verify_attestation` checks announcement signature, outcomes against the descriptor, counts, then **R == announced R before** the library verify. `r_binding_rejects_signature_with_other_r`, Lean `RBinding` |
| 3 | `attestation-engine.ts:156-182,320-339`: nonce derived from index+event only, nothing persisted, any number of values can be signed with the same nonce (nonce reuse reveals the oracle key); `k = oracleKey + tweak` | Nonce is a keyed tagged hash; `Store::begin_use` persists `Fresh -> Used` atomically **before** signing; reuse refused even for the same outcome; single-writer fencing. `nonce_is_single_use`, `persist_before_sign`, `single_writer_fencing`, Lean `Nonce` |
| 4 | `attestation-engine.ts:261-274`: `attestNumeric` accepts `1.5` / `NaN` (digits `"."`, `"N"`) and drops the sign of negative values for unsigned events | integer input, unsigned+negative refused, outcomes checked against the descriptor alphabet. `legacy_numeric_defect_probes_fail_closed_here` |
| 5 | `attestation-engine.ts:320-348`: attestations issued before maturity | `NotMatured` |
| 6 | `attestation-engine.ts:392-409`: undelimited serialisation (`("ab","c")` == `("a","bc")`) | `Enc` length-prefixed encoding; Lean `lp_concat_unambiguous` vs `legacy_concat_ambiguous` |
| 7 | `system-config.ts:166-167,172,229,272`: unknown `NETWORK`/`ORACLE_MODE`/`KEY_PROVIDER`/`LOG_LEVEL` cast unchecked; default provider `mock`; signet mapped to testnet | strict enums, no mock outside development/off mainnet, signet stays signet |
| 8 | `system-config.ts:182-243`: `parseInt` accepts `NaN` and `12abc`; no ranges | strict integer parsing with ranges (ports, BIP-68 delay, dust floor 546 sat, ...) |
| 9 | `system-config.ts:218-222,311`: default API key `dev-key-insecure` rejected only in production (not staging); `CORS_ENABLED !== "false"` and default origin `*` | no default secrets outside development, min length 16, strict booleans, no wildcard CORS outside development |
| 10 | `system-config.ts:306`: server key only checked for non-empty | must parse as a curve point (x-only or compressed) |
| 11 | `event-witness.ts:91-99`: `expectedAmount == 0` -> `NaN` ratio and `totalReceived >= 0` true: "paid" with no payment; duplicates summed twice; recipient/`fromBlock` trusted | zero rejected at construction, dedupe by tx hash, recipient and block filtered, checked sums |
| 12 | `event-witness.ts:295-309`: empty composite `every([]) == true` | empty composite rejected; any child error fails the check |
| 13 | `event-witness.ts:167-177`: price for another pair or any age accepted | pair must match, age bounded, future skew bounded |
| 14 | `ark-tradelayer-handshake.js:124-147,455-510`: Taproot output key is a placeholder (= internal key); merkle path hashed with plain SHA256 (no TapLeaf/TapBranch tags) | real BIP-341 via `bitcoin` crate (`TaprootSpendInfo`, `ControlBlock::verify_taproot_commitment`); registration recomputes the key |
| 15 | `ark-tradelayer-handshake.js:340-422`: template looked up from the **witness**-reconstructed key, not the spent prevout; control block parity/leaf version/internal key unchecked; no annex handling; unconfirmed exit accepted | template from the prevout, commitment verified against the prevout key, internal key and leaf version checked, annex stripped, confirmations required |
| 16 | `ark-tradelayer-handshake.js:515-520`: `compactSize` throws `TypeError` for n >= 253 (`Buffer.concat` receives a number) | delegated to the library (`vectors: compact_size`) |
| 17 | `ark-tradelayer-handshake.js:231-258`: trailing bytes after the witness program accepted, only length 2 checked | strict decoder (exact length, 2..=40, v0 = 20/32) |
| 18 | `ark-tradelayer-handshake.js:32-61`: ids sort `leafScripts` but not `leafRoles`/`leafVersions` (different script/role pairings share an id), `version` not hashed, no delimiters | registry id is `template_id_v2` (order-independent, role-bound, delimited) |
| 19 | `ark-tradelayer-handshake.js:108-111`: `outputKeyIndex.set` silently overwrites an existing output key (rebinding to another ASP) | re-binding to a different `(template, asp)` is `Duplicate` |
| 20 | `ark-tradelayer-handshake.js:570-606`: no memory of minted deposits (same UTXO can back unlimited mints) | per-deposit state machine, `Duplicate` |
| 21 | `ark-tradelayer-handshake.js:611-647`, validation-v2 `:186-192`: burn trusts caller/token-supplied template and ASP; any burn amount | template/ASP taken from the recorded mint; burn amount must equal minted amount |
| 22 | validation-v2 `:114-115,189-191`: `params.fundingVout \|\| params.depositVout` drops vout 0 | `pick_vout` with `Option` |
| 23 | `ark-tradelayer-handshake.js:293,546`: `Math.floor(value*1e8)` float satoshis | integer satoshis, checked sums |

**Versioned protocol changes** (deliberate, not wire-compatible): v1 attestation message and announcement digest
(`TL/ark-dlc/*/v1`); `template_id_v2`; descriptor binary encoding replaces `JSON.stringify(descriptor)` inside the signed
announcement; registration requires hex scripts and an x-only internal key (the legacy sample used `<user_pk>`
placeholders and a 33-byte key and could not register); extra `LoanStatus::EmergencyExited` (legacy enum has no state
for that path); witness amounts/prices are integers; `Store` writer epoch.

**Unresolved questions** (kept as legacy behaviour, pinned by tests, need a human decision)

1. **`emergencyExit` takes 90% for the borrower** (`CollateralizedLoan.ark`): after the exit delay the borrower leaves with
   `collateral - collateral/10` regardless of outstanding principal and without any check that the server is actually
   unavailable. Pinned by `loan::tests::emergency_is_ninety_ten_floor`, `default_and_emergency_boundaries`, Lean
   `emergency_borrower_at_least_ninety`.
2. `liquidate`/`claimDefault` give the lender 100% of the collateral even when collateral value far exceeds the debt.
3. `repayPartial` compares `repaid` with `principal` only; interest is ignored.
4. `released_value` of an exit is the sum of **all** outputs of the spending transaction (legacy "simplified - might want
   to filter by address"), so change/third-party outputs count as released.
5. Redemption is full-redemption-only here (`burn == minted`); legacy had no relation. Partial burns of one VTXO are an open design point.
6. The `.ark` contract checks `sha256(bytes("DLC/oracle/attestation/v0") \|\| outcome)` (plain hash, no event id) whereas the
   TypeScript engine signs the tagged hash; the on-chain script semantics are not ported and the two disagree. A v1
   contract would need to use the v1 message.
7. A template's `merkle_root` cannot be checked against its `leaf_scripts` (the tree shape is not part of the template);
   registration is governance-controlled and the exit path verifies each spend against the registered output key.
8. Unsecured loan accounting (`UnsecuredLoan.ark`) is not ported.

## Not ported

* `LocalKeyProvider` / `CloudKeyProvider` (BIP-39 mnemonics, GCP/AWS secret managers): real-key custody belongs behind a
  reviewed adapter; only `SyntheticKeyProvider` exists.
* `bitcoin-primitives.ts` (cfd-js wrapper): replaced by the `bitcoin`/`secp256k1` crates.
* Mongoose/Redis/BullMQ I/O, the Express API, scheduler and monitoring: the `Store`, `BlockchainClient`, `PriceClient`,
  `ChainView` traits are the boundary; only in-memory implementations exist.
* TradeLayer `property.js` / `tally.js` ledger checks in `validateDLCVTXOBurn` (balance, token metadata): out of scope.
* Ark script execution (`.ark` contracts), unsecured loans, signature/output-script checks of loan settlement transactions.
* Live-network runs: none. CI is written but **will not run until someone pushes**.

## Dependencies

* `bitcoin = "0.32"` (default features off, `std`): `bitcoin_hashes` SHA-256, `secp256k1` (BIP-340 verify, scalar
  arithmetic, x-only keys), BIP-32 for the synthetic provider, BIP-341 `TaprootSpendInfo`/`ControlBlock`. All crypto is
  library code; the offline cargo cache already carries it.
* `serde_json = "1"`: canonical JSON for template timeouts/semantics and test fixtures.

## Commands

```
# from rust/tl-ark-dlc (WSL helper scripts shown in the work tree use rust.sh/lean.sh with the same cargo/lake arguments)
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt --all -- --check
node scripts/v1-vectors.mjs | diff - fixtures/v1_vectors.json
node --experimental-transform-types scripts/compare-legacy.mjs ../.. | diff - fixtures/legacy_vectors.json
cd lean && lake build && lake env lean AxiomCheck.lean
```

Last local run: 70 tests pass (4 unit, 66 integration), clippy `-D warnings` clean, `fmt --check` clean, Lean build OK with
only `propext`/`Quot.sound`/`Classical.choice` axioms.

## Lean 4 (`lean/`, core Lean only, no Mathlib, no `sorry`)

| Lean module | Models (Rust) | Theorems |
| --- | --- | --- |
| `Nonce` | `Store::begin_use`, `acquire_writer`, `Oracle::attest` order | `no_two_signatures_share_a_nonce`, `begin_use_refuses_reuse`, `reuse_refused_after_use`, `signature_implies_persisted`, `second_signature_refused`, `stale_writer_refused`, `takeover_invalidates_old_token`, `begin_all_ok_marks_all`, `begin_all_duplicate_refused`, `inv_preserved_use` |
| `RBinding` | R loop of `verify_attestation`, `r_binding_ok` | `accepted_implies_bound`, `wrong_r_rejected`, `length_mismatch_rejected`, `distinct_announcements_do_not_accept_each_others_signatures`, `r_bind_iff` |
| `Binding` | `attestation_digest`, `Enc::lp`, tagged hash | `encode_injective`, `event_binding`, `digest_injective`, `digest_event_binding`, `announcement_is_not_attestation`, `attestation_for_a_not_valid_for_b`, `lp_concat_unambiguous`, `legacy_concat_ambiguous`, `legacy_not_event_bound` |
| `Loan` | `split_*`, `LoanStatus::can_transition_to`, `Loan` methods | `repay_partial_sum`, `repay_partial_ratio_lt`, `emergency_sum`, `emergency_borrower_at_least_ninety`, `emergency_lender_at_most_ten`, `to_lender_sum`, `full_sum`, `step_follows_allowed_edges`, `terminal_has_no_step`, `terminal_has_no_edge`, `terminal_reaches_only_itself`, `pending_only_to_active`, `nothing_returns_to_pending`, `reach_from_pending` |

Abstractions: nonce keys / digests / event ids are `Nat`; the `u32` length prefix is one cell; fixed 32-byte fields are
32 cells (`WF`); the hash is an arbitrary function and collision resistance is the explicit hypothesis `Injective H` (so
the theorems say: any cross-event collision would be a hash collision, never an encoding ambiguity); money is `Nat`
(Rust uses `u64` with `u128` intermediates and checked arithmetic); the BIP-340 verification is the abstract predicate
`valid`; lifecycle guards (proofs, time, amounts) are abstracted away because they can only make a step fail. `example`
lines in the Lean files restate the concrete Rust test vectors (`repayPartial 1000000 300000 100000 = 333333/666667`,
`emergency 1000005`, `begin_use` reuse/stale cases). Hash outputs are not computable in Lean, so digests are checked by the
Node-independent vectors on the Rust side only.

## Remaining gaps (honest list)

* Not audited. The `s = k + e*d` signing composition is validated by library verification in dozens of signing runs in tests (40 events in one test alone), not by
  an external test-vector suite for this path.
* The oracle key and the nonce-derivation input pass through ordinary `Vec`s (no zeroisation); fine for synthetic keys only.
* Legacy signature vectors (cfd-js) were not obtainable offline.
* `Config` does not validate BIP-39 mnemonics (not ported).
* No performance work, no async, no persistence beyond `MemoryStore` (its durability behaviour is simulated by failure hooks).
