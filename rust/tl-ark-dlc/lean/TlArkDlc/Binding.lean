/-!
# Event binding and domain separation

Models `attestation_digest` (and `Enc`) of `attestation.rs`:

```
digest = H( tag_attestation, pk(32) ‖ lp(event_id) ‖ announcement_digest(32) ‖ index ‖ R(32) ‖ lp(outcome) )
```

Abstractions: bytes are `Nat` cells; the `u32` big-endian length prefix of `Enc::lp` is one cell
holding the length (equivalent as long as lengths fit in `u32`, which `Enc::lp` enforces with
`MAX_FIELD_LEN = 65536`); the `u32` index is one cell; the three 32-byte fields are exactly 32
cells (`WF`). The hash `H` is an arbitrary function from tagged payloads to digests; where a
theorem needs collision resistance it takes it as the explicit hypothesis `Injective H` (not an
axiom): the proofs show that no *encoding* ambiguity exists, i.e. all collisions would have to be
collisions of SHA-256 itself.
-/

namespace TlArkDlc.Binding

abbrev Bytes := List Nat

/-- Length-prefixed field (`Enc::lp`). -/
def lp (b : Bytes) : Bytes := b.length :: b

structure Msg where
  pk : Bytes
  eid : Bytes
  annDigest : Bytes
  idx : Nat
  r : Bytes
  outcome : Bytes
  deriving DecidableEq, Repr

/-- The three fixed-width fields have their 32-byte width. -/
def WF (m : Msg) : Prop :=
  m.pk.length = 32 ∧ m.annDigest.length = 32 ∧ m.r.length = 32

/-- Byte layout of the attestation message body. -/
def encode (m : Msg) : Bytes :=
  m.pk ++ (lp m.eid ++ (m.annDigest ++ ([m.idx] ++ (m.r ++ lp m.outcome))))

theorem lp_inj {a b t u : Bytes} (h : lp a ++ t = lp b ++ u) : a = b ∧ t = u := by
  simp only [lp, List.cons_append, List.cons.injEq] at h
  exact List.append_inj h.2 h.1

/-- The encoding is injective on well-formed messages: no two different
`(pk, event, announcement, index, R, outcome)` tuples have the same bytes. -/
theorem encode_injective {m₁ m₂ : Msg} (w₁ : WF m₁) (w₂ : WF m₂)
    (h : encode m₁ = encode m₂) : m₁ = m₂ := by
  obtain ⟨hpk, h⟩ := List.append_inj h (by rw [w₁.1, w₂.1])
  obtain ⟨he, h⟩ := lp_inj h
  obtain ⟨had, h⟩ := List.append_inj h (by rw [w₁.2.1, w₂.2.1])
  simp only [List.singleton_append, List.cons.injEq] at h
  obtain ⟨hi, h⟩ := h
  obtain ⟨hr, h⟩ := List.append_inj h (by rw [w₁.2.2, w₂.2.2])
  simp only [lp, List.cons.injEq] at h
  obtain ⟨_, ho⟩ := h
  cases m₁
  cases m₂
  simp_all

/-- Different event ids give different message bytes. -/
theorem event_binding {m₁ m₂ : Msg} (w₁ : WF m₁) (w₂ : WF m₂) (h : m₁.eid ≠ m₂.eid) :
    encode m₁ ≠ encode m₂ := by
  intro he
  exact h (congrArg Msg.eid (encode_injective w₁ w₂ he))

inductive Tag where
  | announcement
  | attestation
  deriving DecidableEq

/-- Domain separation: the hash input is the tag together with the payload
(`tagged_hash(tag, data)` hashes `SHA256(tag)‖SHA256(tag)‖data`). -/
def tagged (t : Tag) (b : Bytes) : Tag × Bytes := (t, b)

def digest (H : Tag × Bytes → Nat) (m : Msg) : Nat := H (tagged .attestation (encode m))

def Injective (H : Tag × Bytes → Nat) : Prop := ∀ a b, H a = H b → a = b

theorem digest_injective {H : Tag × Bytes → Nat} (hH : Injective H) {m₁ m₂ : Msg}
    (w₁ : WF m₁) (w₂ : WF m₂) (h : digest H m₁ = digest H m₂) : m₁ = m₂ := by
  have := hH _ _ h
  simp only [tagged, Prod.mk.injEq, true_and] at this
  exact encode_injective w₁ w₂ this

theorem digest_event_binding {H : Tag × Bytes → Nat} (hH : Injective H) {m₁ m₂ : Msg}
    (w₁ : WF m₁) (w₂ : WF m₂) (h : m₁.eid ≠ m₂.eid) : digest H m₁ ≠ digest H m₂ := by
  intro hd
  exact h (congrArg Msg.eid (digest_injective hH w₁ w₂ hd))

/-- An announcement digest and an attestation digest never coincide. -/
theorem announcement_is_not_attestation {H : Tag × Bytes → Nat} (hH : Injective H)
    (x y : Bytes) : H (tagged .announcement x) ≠ H (tagged .attestation y) := by
  intro h
  have := hH _ _ h
  simp [tagged] at this

/-- The oracle accepts (has signed) a message iff its digest is among the signed digests. -/
def accepts (H : Tag × Bytes → Nat) (signed : List Nat) (m : Msg) : Prop :=
  digest H m ∈ signed

/-- An attestation made for event A never verifies as event B: if every digest the oracle
signed belongs to some well-formed message of event A, a well-formed message of a different
event B is not accepted. -/
theorem attestation_for_a_not_valid_for_b {H : Tag × Bytes → Nat} (hH : Injective H)
    (signed : List Nat) (a : Bytes) (mB : Msg) (wB : WF mB) (hne : mB.eid ≠ a)
    (hsigned : ∀ d ∈ signed, ∃ m', WF m' ∧ m'.eid = a ∧ d = digest H m') :
    ¬ accepts H signed mB := by
  intro hacc
  obtain ⟨m', w', he, hd⟩ := hsigned _ hacc
  have := digest_injective hH wB w' hd
  exact hne (by rw [this]; exact he)

/-- Legacy message: `H_attestation_v0(outcome)` — nothing but the outcome is signed. -/
def legacyMsg (m : Msg) : Bytes := m.outcome

/-- The legacy message is not event bound: two different events, one signed message. -/
theorem legacy_not_event_bound :
    ∃ a b : Msg, a.eid ≠ b.eid ∧ legacyMsg a = legacyMsg b :=
  ⟨⟨[], [1], [], 0, [], [7]⟩, ⟨[], [2], [], 0, [], [7]⟩, by decide, rfl⟩

/-- Legacy announcement serialisation concatenates without delimiters (ambiguous)… -/
theorem legacy_concat_ambiguous :
    ∃ a b c d : Bytes, (a, b) ≠ (c, d) ∧ a ++ b = c ++ d :=
  ⟨[1], [2, 3], [1, 2], [3], by decide, rfl⟩

/-- …while the length-prefixed encoding is not. -/
theorem lp_concat_unambiguous (a b c d : Bytes) (h : lp a ++ lp b = lp c ++ lp d) :
    a = c ∧ b = d := by
  obtain ⟨hac, h2⟩ := lp_inj h
  obtain ⟨hbd, _⟩ := lp_inj (t := []) (u := []) (by simpa using h2)
  exact ⟨hac, hbd⟩

-- Concrete layout (same shape as the Rust unit tests; widths shrunk for readability).
example : encode ⟨[1], [7, 8], [3], 0, [5], [9]⟩ = [1, 2, 7, 8, 3, 0, 5, 1, 9] := by rfl
example : encode ⟨[1], [7, 8], [3], 1, [5], [9]⟩ ≠ encode ⟨[1], [7, 8], [3], 0, [5], [9]⟩ := by
  decide

end TlArkDlc.Binding
