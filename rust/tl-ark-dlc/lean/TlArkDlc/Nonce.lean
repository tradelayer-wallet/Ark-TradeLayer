/-!
# Nonce single use and single-writer control

Models `Store::begin_use` / `Store::acquire_writer` of `storage.rs` and the
persist-before-sign order of `Oracle::attest` in `attestation.rs`.

Abstractions: an event id and an outcome index are `Nat`s, a message digest is a `Nat`;
`used` is the set of nonces whose state is `Used`, `log` is the append-only record of
`(nonce, digest)` pairs that were authorised for signing, `epoch` is the writer fencing epoch.
`MemoryStore::begin_use` is all-or-nothing over a batch; `beginAll` models that.
-/

namespace TlArkDlc.Nonce

/-- A nonce is identified by `(event id, outcome index)`. -/
abbrev Key := Nat × Nat

structure St where
  used : List Key
  log : List (Key × Nat)
  epoch : Nat
  deriving Repr

inductive Err where
  | stale
  | reuse
  deriving DecidableEq, Repr

/-- `Store::begin_use` for one nonce: fenced by the writer epoch, refuses a used nonce,
otherwise marks it used and appends `(key, digest)` to the log. -/
def beginUse (s : St) (e : Nat) (k : Key) (d : Nat) : Except Err St :=
  if e ≠ s.epoch then .error .stale
  else if k ∈ s.used then .error .reuse
  else .ok { s with used := k :: s.used, log := (k, d) :: s.log }

/-- `Store::acquire_writer`: a new epoch; every older token becomes stale. -/
def acquire (s : St) : St := { s with epoch := s.epoch + 1 }

/-- Batch `begin_use`: all nonces or none (the first failure aborts the whole batch). -/
def beginAll (s : St) (e : Nat) : List (Key × Nat) → Except Err St
  | [] => .ok s
  | (k, d) :: rest =>
      match beginUse s e k d with
      | .error x => .error x
      | .ok s' => beginAll s' e rest

/-- `Oracle::attest` for one nonce: a signature `(k, d)` exists only as the result of a
successful persist. -/
def sign (s : St) (e : Nat) (k : Key) (d : Nat) : Except Err (St × (Key × Nat)) :=
  match beginUse s e k d with
  | .error x => .error x
  | .ok s' => .ok (s', (k, d))

def init (epoch : Nat) : St := { used := [], log := [], epoch := epoch }

/-- States reachable from a fresh store by successful `beginUse` and `acquire` steps. -/
inductive Reachable : St → Prop
  | init (n : Nat) : Reachable (init n)
  | use {s s' : St} (e : Nat) (k : Key) (d : Nat) :
      Reachable s → beginUse s e k d = .ok s' → Reachable s'
  | takeover {s : St} : Reachable s → Reachable (acquire s)

/-- Invariant: the log records exactly the used nonces, each once. -/
def Inv (s : St) : Prop := s.log.map Prod.fst = s.used ∧ s.used.Nodup

theorem inv_init (n : Nat) : Inv (init n) := by
  simp [Inv, init]

theorem begin_use_refuses_reuse (s : St) (k : Key) (d : Nat) (h : k ∈ s.used) :
    beginUse s s.epoch k d = .error .reuse := by
  simp [beginUse, h]

theorem stale_writer_refused (s : St) (e : Nat) (k : Key) (d : Nat) (h : e ≠ s.epoch) :
    beginUse s e k d = .error .stale := by
  simp [beginUse, h]

theorem begin_use_marks_used (s s' : St) (e : Nat) (k : Key) (d : Nat)
    (h : beginUse s e k d = .ok s') : k ∈ s'.used ∧ (k, d) ∈ s'.log := by
  unfold beginUse at h
  split at h
  · cases h
  · split at h
    · cases h
    · cases h; simp

theorem inv_preserved_use (s s' : St) (e : Nat) (k : Key) (d : Nat) (hi : Inv s)
    (h : beginUse s e k d = .ok s') : Inv s' := by
  unfold beginUse at h
  split at h
  · cases h
  · rename_i hne
    split at h
    · cases h
    · rename_i hk
      cases h
      obtain ⟨h1, h2⟩ := hi
      refine ⟨by simp [h1], ?_⟩
      simp [List.nodup_cons, hk, h2]

theorem inv_preserved_takeover (s : St) (hi : Inv s) : Inv (acquire s) := by
  simpa [Inv, acquire] using hi

theorem reachable_inv {s : St} (h : Reachable s) : Inv s := by
  induction h with
  | init n => exact inv_init n
  | use e k d _ hs ih => exact inv_preserved_use _ _ e k d ih hs
  | takeover _ ih => exact inv_preserved_takeover _ ih

/-- No two signatures ever share a nonce: the keys of everything authorised for signing are
pairwise distinct in every reachable store state. -/
theorem no_two_signatures_share_a_nonce {s : St} (h : Reachable s) :
    (s.log.map Prod.fst).Nodup := by
  have hi := reachable_inv h
  rw [hi.1]
  exact hi.2

/-- Once a nonce is used, a later request with the current token and *any* digest is refused. -/
theorem reuse_refused_after_use {s s' : St} {e : Nat} {k : Key} {d d' : Nat}
    (h : beginUse s e k d = .ok s') : beginUse s' s'.epoch k d' = .error .reuse := by
  have hk := (begin_use_marks_used s s' e k d h).1
  exact begin_use_refuses_reuse s' k d' hk

/-- Persist-before-sign: a signature is returned only together with a store state in which
its nonce is already marked used, and a second signature with that nonce is refused. -/
theorem signature_implies_persisted {s s' : St} {e : Nat} {k : Key} {d : Nat} {sg : Key × Nat}
    (h : sign s e k d = .ok (s', sg)) : sg.1 ∈ s'.used ∧ sg = (k, d) := by
  unfold sign at h
  split at h
  · cases h
  · rename_i s'' hb
    cases h
    exact ⟨(begin_use_marks_used s _ e k d hb).1, rfl⟩

theorem second_signature_refused {s s' : St} {e : Nat} {k : Key} {d d' : Nat} {sg : Key × Nat}
    (h : sign s e k d = .ok (s', sg)) : sign s' s'.epoch k d' = .error .reuse := by
  unfold sign at h
  split at h
  · cases h
  · rename_i s'' hb
    cases h
    have := reuse_refused_after_use (d' := d') hb
    simp [sign, this]

/-- After a takeover, the previous writer's token is stale. -/
theorem takeover_invalidates_old_token (s : St) (k : Key) (d : Nat) :
    beginUse (acquire s) s.epoch k d = .error .stale := by
  apply stale_writer_refused
  simp [acquire]

theorem begin_use_mono (s s' : St) (e : Nat) (k : Key) (d : Nat)
    (h : beginUse s e k d = .ok s') : ∀ y, y ∈ s.used → y ∈ s'.used := by
  unfold beginUse at h
  split at h
  · cases h
  · split at h
    · cases h
    · cases h
      intro y hy
      simp [hy]

theorem begin_all_mono (s s' : St) (e : Nat) (l : List (Key × Nat))
    (h : beginAll s e l = .ok s') : ∀ y, y ∈ s.used → y ∈ s'.used := by
  induction l generalizing s with
  | nil =>
      simp [beginAll] at h
      subst h
      intro y hy
      exact hy
  | cons hd rest ih =>
      obtain ⟨k, d⟩ := hd
      unfold beginAll at h
      split at h
      · cases h
      · rename_i s1 hb
        intro y hy
        exact ih s1 h y (begin_use_mono _ _ _ _ _ hb y hy)

/-- A batch that succeeds marked every nonce of the batch as used (all-or-nothing: on any
failure `beginAll` returns an error and no state). -/
theorem begin_all_ok_marks_all (s s' : St) (e : Nat) (l : List (Key × Nat))
    (h : beginAll s e l = .ok s') : ∀ x ∈ l, x.1 ∈ s'.used := by
  induction l generalizing s with
  | nil => simp
  | cons hd rest ih =>
      obtain ⟨k, d⟩ := hd
      unfold beginAll at h
      split at h
      · cases h
      · rename_i s1 hb
        intro x hx
        rcases List.mem_cons.mp hx with rfl | hx
        · exact begin_all_mono s1 s' e rest h _ (begin_use_marks_used _ _ _ _ _ hb).1
        · exact ih s1 h x hx

/-- A batch containing the same nonce twice is refused. -/
theorem begin_all_duplicate_refused (s : St) (k : Key) (d d' : Nat) :
    beginAll s s.epoch [(k, d), (k, d')] = .error .reuse := by
  by_cases hm : k ∈ s.used
  · simp [beginAll, beginUse, hm]
  · simp [beginAll, beginUse, hm]

example : beginUse (init 1) 1 (7, 0) 5 = .ok ⟨[(7, 0)], [((7, 0), 5)], 1⟩ := by rfl
example : beginUse ⟨[(7, 0)], [((7, 0), 5)], 1⟩ 1 (7, 0) 6 = .error .reuse := by rfl
example : beginUse (init 2) 1 (7, 0) 5 = .error .stale := by rfl

end TlArkDlc.Nonce
