/-!
# Announced-R binding

Models the R-binding loop of `verify_attestation` in `attestation.rs`: outcome `i` is accepted
only if the signature's nonce point equals the announced nonce point at index `i`
(`r_binding_ok`), and only then is the (library) signature check run (`valid`, abstract here).
A prior review found R binding was off-chain only; the legacy `verifyAttestation` never compared R.
-/

namespace TlArkDlc.RBinding

/-- x-only nonce point (abstract). -/
abbrev Pt := Nat

/-- A signature `R || s`; only `R` matters for binding. -/
structure Sig where
  r : Pt
  s : Nat
  deriving DecidableEq, Repr

/-- `r_binding_ok(announced_r, signature)`. -/
def rBind (announced : Pt) (sg : Sig) : Bool := sg.r == announced

/-- The loop of `verify_attestation`: lengths must agree, and at every index the announced R
must equal the signature's R before the signature check `valid i sg` is consulted. -/
def verifyAll (valid : Nat → Sig → Bool) : Nat → List Pt → List Sig → Bool
  | _, [], [] => true
  | i, r :: rs, sg :: sgs => rBind r sg && valid i sg && verifyAll valid (i + 1) rs sgs
  | _, _, _ => false

theorem r_bind_iff (r : Pt) (sg : Sig) : rBind r sg = true ↔ sg.r = r := by
  simp [rBind]

/-- Acceptance implies R-binding at every index (and the signature check passed there). -/
theorem accepted_implies_bound (valid : Nat → Sig → Bool) :
    ∀ (rs : List Pt) (sgs : List Sig) (i : Nat),
      verifyAll valid i rs sgs = true →
      ∀ j r sg, rs[j]? = some r → sgs[j]? = some sg → sg.r = r ∧ valid (i + j) sg = true := by
  intro rs
  induction rs with
  | nil =>
      intro sgs i _ j r sg h1
      simp at h1
  | cons r0 rs ih =>
      intro sgs i h j r sg h1 h2
      cases sgs with
      | nil => simp [verifyAll] at h
      | cons sg0 sgs =>
          simp [verifyAll, rBind] at h
          obtain ⟨⟨hr, hv⟩, hrest⟩ := h
          cases j with
          | zero =>
              simp at h1 h2
              subst h1
              subst h2
              simpa using ⟨hr, hv⟩
          | succ j =>
              simp at h1 h2
              have := ih sgs (i + 1) hrest j r sg h1 h2
              have e : i + 1 + j = i + (j + 1) := by omega
              rw [e] at this
              exact this

/-- A single wrong R anywhere is rejected, whatever the signature check says. -/
theorem wrong_r_rejected (valid : Nat → Sig → Bool) (rs : List Pt) (sgs : List Sig) (i : Nat)
    (j : Nat) (r : Pt) (sg : Sig) (h1 : rs[j]? = some r) (h2 : sgs[j]? = some sg)
    (hne : sg.r ≠ r) : verifyAll valid i rs sgs = false := by
  cases hv : verifyAll valid i rs sgs with
  | false => rfl
  | true => exact absurd (accepted_implies_bound valid rs sgs i hv j r sg h1 h2).1 hne

/-- Missing or extra signatures are rejected. -/
theorem length_mismatch_rejected (valid : Nat → Sig → Bool) :
    ∀ (rs : List Pt) (sgs : List Sig) (i : Nat),
      rs.length ≠ sgs.length → verifyAll valid i rs sgs = false := by
  intro rs
  induction rs with
  | nil =>
      intro sgs i h
      cases sgs with
      | nil => simp at h
      | cons _ _ => simp [verifyAll]
  | cons r rs ih =>
      intro sgs i h
      cases sgs with
      | nil => simp [verifyAll]
      | cons sg sgs =>
          have h' : rs.length ≠ sgs.length := by simpa using h
          simp [verifyAll, ih sgs (i + 1) h']

/-- An announcement with an alternative R list never accepts a signature made for another:
if the two announced lists differ at some index, a signature vector bound to one is rejected
by the other. -/
theorem distinct_announcements_do_not_accept_each_others_signatures
    (valid : Nat → Sig → Bool) (rs₁ rs₂ : List Pt) (sgs : List Sig) (i : Nat)
    (j : Nat) (r₁ r₂ : Pt) (h1 : rs₁[j]? = some r₁) (h2 : rs₂[j]? = some r₂) (hne : r₁ ≠ r₂)
    (hsg : ∀ (k : Nat) (r : Pt), rs₁[k]? = some r → ∃ sg : Sig, sgs[k]? = some sg ∧ sg.r = r)
    : verifyAll valid i rs₂ sgs = false := by
  obtain ⟨sg, hs, hr⟩ := hsg j r₁ h1
  exact wrong_r_rejected valid rs₂ sgs i j r₂ sg h2 hs (by rw [hr]; exact hne)

example : verifyAll (fun _ _ => true) 0 [1, 2] [⟨1, 9⟩, ⟨2, 9⟩] = true := by rfl
example : verifyAll (fun _ _ => true) 0 [1, 2] [⟨1, 9⟩, ⟨3, 9⟩] = false := by rfl
example : verifyAll (fun _ _ => true) 0 [1, 2] [⟨1, 9⟩] = false := by rfl

end TlArkDlc.RBinding
