/-!
# Loan value accounting and lifecycle edges

Models `split_repay_partial`, `split_emergency`, `split_to_lender`, `split_repay_full` and
`LoanStatus::can_transition_to` / `Loan` methods of `loan.rs`. Amounts are `Nat` (satoshis); the
Rust code uses `u64` with `u128` intermediates and checked arithmetic, so it agrees with this
model wherever it does not return `Overflow` (which `u128` intermediates make impossible for the
partial split: `collateral * 1e6 < 2^84`).
-/

namespace TlArkDlc.Loan

def scale : Nat := 1000000

structure Split where
  borrower : Nat
  lender : Nat
  deriving DecidableEq, Repr

/-- `split_repay_partial(collateral, principal, repaid)`. -/
def repayPartial (c p r : Nat) : Option Split :=
  if p = 0 ∨ r = 0 ∨ p ≤ r then none
  else
    let ratio := r * scale / p
    let lender := c * (scale - ratio) / scale
    some ⟨c - lender, lender⟩

/-- `split_emergency`: `penalty = collateral / 10` to the lender, the rest to the borrower. -/
def emergency (c : Nat) : Split := ⟨c - c / 10, c / 10⟩

/-- `split_to_lender` (liquidation, default). -/
def toLender (c : Nat) : Split := ⟨0, c⟩

/-- `split_repay_full`. -/
def full (c : Nat) : Split := ⟨c, 0⟩

theorem repay_partial_sum {c p r : Nat} {s : Split} (h : repayPartial c p r = some s) :
    s.borrower + s.lender = c := by
  unfold repayPartial at h
  split at h
  · cases h
  · simp only [Option.some.injEq] at h
    subst h
    have hle : c * (scale - r * scale / p) / scale ≤ c := by
      apply Nat.div_le_of_le_mul
      have : scale - r * scale / p ≤ scale := Nat.sub_le _ _
      calc c * (scale - r * scale / p) ≤ c * scale := Nat.mul_le_mul_left c this
        _ = scale * c := Nat.mul_comm _ _
    simp only
    omega

/-- The ratio stays below the scale for `0 < r < p`, so a partial repayment never gives the
borrower the whole collateral by rounding: the lender's share is at least `c * (scale - ratio) / scale`
and `ratio < scale`. -/
theorem repay_partial_ratio_lt {p r : Nat} (_hp : 0 < p) (hr : r < p) : r * scale / p < scale := by
  apply Nat.div_lt_of_lt_mul
  have : r * scale < p * scale := Nat.mul_lt_mul_of_pos_right hr (by decide)
  exact this

theorem repay_partial_rejects_out_of_range (c p r : Nat) (h : p = 0 ∨ r = 0 ∨ p ≤ r) :
    repayPartial c p r = none := by
  simp [repayPartial, h]

theorem emergency_sum (c : Nat) : (emergency c).borrower + (emergency c).lender = c := by
  simp only [emergency]
  omega

/-- The borrower's emergency-exit share is at least 90% (the unresolved question: it is paid
whenever the exit delay has passed, independent of any outstanding principal). -/
theorem emergency_borrower_at_least_ninety (c : Nat) : 9 * c ≤ 10 * (emergency c).borrower := by
  simp only [emergency]
  omega

theorem emergency_lender_at_most_ten (c : Nat) : 10 * (emergency c).lender ≤ c := by
  simp only [emergency]
  omega

theorem to_lender_sum (c : Nat) : (toLender c).borrower + (toLender c).lender = c := by
  simp [toLender]

theorem full_sum (c : Nat) : (full c).borrower + (full c).lender = c := by
  simp [full]

-- Concrete vectors, identical to the Rust unit tests in loan.rs.
example : repayPartial 1000000 300000 100000 = some ⟨333333, 666667⟩ := by decide
example : emergency 1000005 = ⟨900005, 100000⟩ := by decide
example : emergency 9 = ⟨9, 0⟩ := by decide
example : repayPartial 10 100 0 = none := by decide
example : repayPartial 10 100 100 = none := by decide

/-! ## Lifecycle -/

inductive Status where
  | pending | active | repaid | defaulted | liquidated | disputed | emergencyExited
  deriving DecidableEq, Repr

/-- `LoanStatus::can_transition_to`. -/
def allowed : Status → Status → Bool
  | .pending, .active => true
  | .active, .repaid => true
  | .active, .defaulted => true
  | .active, .liquidated => true
  | .active, .disputed => true
  | .active, .emergencyExited => true
  | .disputed, .repaid => true
  | .disputed, .defaulted => true
  | .disputed, .liquidated => true
  | .disputed, .emergencyExited => true
  | _, _ => false

/-- `LoanStatus::is_terminal`. -/
def isTerminal : Status → Bool
  | .repaid | .defaulted | .liquidated | .emergencyExited => true
  | _ => false

inductive Ev where
  | fund | repayFull | repayPartial | liquidate | claimDefault | emergencyExit
  | dispute | resolveBorrower | resolveLender
  deriving DecidableEq, Repr

/-- The state each `Loan` method moves to (guards on proofs, time and amounts are abstracted:
they can only make a step fail, never create an edge). -/
def step : Status → Ev → Option Status
  | .pending, .fund => some .active
  | .active, .repayFull => some .repaid
  | .active, .repayPartial => some .repaid
  | .active, .liquidate => some .liquidated
  | .active, .claimDefault => some .defaulted
  | .active, .emergencyExit => some .emergencyExited
  | .active, .dispute => some .disputed
  | .disputed, .resolveBorrower => some .repaid
  | .disputed, .resolveLender => some .defaulted
  | _, _ => none

/-- Transitions only along allowed edges. -/
theorem step_follows_allowed_edges (s : Status) (e : Ev) (t : Status)
    (h : step s e = some t) : allowed s t = true := by
  cases s <;> cases e <;> simp [step] at h <;> (try subst h) <;> rfl

/-- Terminal states have no outgoing event. -/
theorem terminal_has_no_step (s : Status) (hs : isTerminal s = true) (e : Ev) :
    step s e = none := by
  cases s <;> cases e <;> simp_all [step, isTerminal]

theorem terminal_has_no_edge (s : Status) (hs : isTerminal s = true) (t : Status) :
    allowed s t = false := by
  cases s <;> cases t <;> simp_all [allowed, isTerminal]

/-- The only way out of `pending` is to `active`. -/
theorem pending_only_to_active (t : Status) (h : allowed .pending t = true) : t = .active := by
  cases t <;> simp_all [allowed]

/-- Nothing ever returns to `pending`. -/
theorem nothing_returns_to_pending (s : Status) : allowed s .pending = false := by
  cases s <;> simp [allowed]

inductive Reach : Status → Status → Prop
  | refl (s : Status) : Reach s s
  | step {s t u : Status} (e : Ev) : step s e = some t → Reach t u → Reach s u

/-- A settled loan stays settled: from a terminal state only the state itself is reachable. -/
theorem terminal_reaches_only_itself {s t : Status} (hs : isTerminal s = true)
    (h : Reach s t) : t = s := by
  cases h with
  | refl => rfl
  | step e he _ => simp [terminal_has_no_step s hs e] at he

/-- Every state reachable from `pending` other than `pending` itself is reached through `active`. -/
theorem reach_from_pending {t : Status} (h : Reach .pending t) (hne : t ≠ .pending) :
    Reach .active t := by
  cases h with
  | refl => exact absurd rfl hne
  | step e he hr =>
      cases e <;> simp [step] at he
      subst he
      exact hr

example : step .pending .fund = some .active := by rfl
example : step .repaid .claimDefault = none := by rfl
example : step .pending .repayFull = none := by rfl
example : allowed .active .emergencyExited = true := by rfl

end TlArkDlc.Loan
