//! Oracle announcements and attestations (DLC style) with event binding, announced-R binding and
//! single-use nonces.
//!
//! Source: `vtxo-loan-system/src/attestation/attestation-engine.ts` and
//! `src/crypto/tagged-hash.ts`. Legacy byte layouts (for parity vectors) live in [`crate::legacy`].
//!
//! Differences from the legacy engine (all recorded in the README table):
//! * the signed message binds oracle key, event id, announcement digest, outcome index, announced
//!   R and outcome under the `TL/ark-dlc/oracle-attestation/v1` tag (legacy signed only
//!   `H(outcome)`, so an attestation for event A verified for any event with the same outcome);
//! * verification requires the signature's R to equal the announced R for that index (legacy never
//!   compared R with the announcement);
//! * nonces are single use: the use is persisted (`Store::begin_use`) **before** signing, and a
//!   second attestation for any of the same nonces is refused (legacy re-derived the same nonce for
//!   any value, so two different outcomes could be signed with one nonce, which leaks the key);
//! * attestations are refused before maturity and outcomes are checked against the descriptor.
//!
//! The only secp256k1 arithmetic done here is `s = k + e*d` on library `SecretKey`/`Scalar` types;
//! every produced signature is re-verified with the library's BIP-340 verifier before it is
//! returned. Keys are synthetic/test keys only.

use bitcoin::secp256k1::{
    schnorr, Keypair, Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};

use crate::error::{Error, Result};
use crate::hash::{tagged_hash, Enc};
use crate::storage::{
    AttestationRecord, EventAnnouncementRecord, EventType, NonceUse, Store, WriterToken,
};
use crate::util::check_ident;

/// Tag of the announcement digest.
pub const DOMAIN_ANNOUNCEMENT: &str = "TL/ark-dlc/oracle-announcement/v1";
/// Tag of the attestation message digest.
pub const DOMAIN_ATTESTATION: &str = "TL/ark-dlc/oracle-attestation/v1";
/// Tag of the nonce derivation.
pub const DOMAIN_NONCE: &str = "TL/ark-dlc/oracle-nonce/v1";
/// Max length of an event id.
pub const MAX_EVENT_ID_LEN: usize = 128;
/// Max length of one outcome label.
pub const MAX_OUTCOME_LEN: usize = 128;
/// Max enum outcomes.
pub const MAX_OUTCOMES: usize = 256;
/// Max numeric digits.
pub const MAX_DIGITS: u16 = 64;

const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// Numeric event descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NumericDescriptor {
    /// Digit base, 2..=36.
    pub base: u8,
    /// Number of digits, 1..=64.
    pub num_digits: u16,
    /// Unit label.
    pub unit: String,
    /// Decimal precision.
    pub precision: u8,
    /// Whether a sign outcome precedes the digits.
    pub signed: bool,
}

/// Event descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Descriptor {
    /// Enumerated outcomes.
    Enum {
        /// Possible outcomes.
        outcomes: Vec<String>,
    },
    /// Binary outcome: `outcomes[0]` is `true`.
    Binary {
        /// Labels.
        outcomes: [String; 2],
    },
    /// Numeric.
    Numeric(NumericDescriptor),
}

fn check_outcome_label(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::Malformed("empty outcome label"));
    }
    if s.len() > MAX_OUTCOME_LEN {
        return Err(Error::TooLarge("outcome label"));
    }
    if s.chars().any(|c| c.is_control()) {
        return Err(Error::Malformed("control character in outcome"));
    }
    Ok(())
}

impl Descriptor {
    /// Event type.
    pub fn event_type(&self) -> EventType {
        match self {
            Descriptor::Enum { .. } => EventType::Enum,
            Descriptor::Binary { .. } => EventType::Binary,
            Descriptor::Numeric(_) => EventType::Numeric,
        }
    }

    /// Structural validation.
    pub fn validate(&self) -> Result<()> {
        match self {
            Descriptor::Enum { outcomes } => {
                if outcomes.is_empty() {
                    return Err(Error::Malformed("enum needs outcomes"));
                }
                if outcomes.len() > MAX_OUTCOMES {
                    return Err(Error::TooLarge("enum outcomes"));
                }
                for (i, o) in outcomes.iter().enumerate() {
                    check_outcome_label(o)?;
                    if outcomes[..i].contains(o) {
                        return Err(Error::Duplicate("enum outcome"));
                    }
                }
            }
            Descriptor::Binary { outcomes } => {
                check_outcome_label(&outcomes[0])?;
                check_outcome_label(&outcomes[1])?;
                if outcomes[0] == outcomes[1] {
                    return Err(Error::Duplicate("binary outcome"));
                }
            }
            Descriptor::Numeric(n) => {
                if !(2..=36).contains(&n.base) {
                    return Err(Error::Malformed("numeric base"));
                }
                if n.num_digits == 0 || n.num_digits > MAX_DIGITS {
                    return Err(Error::Malformed("numeric digit count"));
                }
                if n.unit.len() > 16 || n.unit.chars().any(|c| c.is_control()) {
                    return Err(Error::Malformed("numeric unit"));
                }
            }
        }
        Ok(())
    }

    /// Number of nonces (= outcome signatures) needed: legacy `calculateNoncesNeeded`.
    pub fn nonces_needed(&self) -> usize {
        match self {
            Descriptor::Numeric(n) => usize::from(n.num_digits) + usize::from(n.signed),
            _ => 1,
        }
    }

    /// Canonical, unambiguous binary encoding (replaces legacy `JSON.stringify(descriptor)`).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Enc::new();
        match self {
            Descriptor::Enum { outcomes } => {
                e.u8(1).u32(outcomes.len() as u32);
                for o in outcomes {
                    e.lp(o.as_bytes())?;
                }
            }
            Descriptor::Binary { outcomes } => {
                e.u8(2);
                e.lp(outcomes[0].as_bytes())?;
                e.lp(outcomes[1].as_bytes())?;
            }
            Descriptor::Numeric(n) => {
                e.u8(3).u8(n.base).u32(u32::from(n.num_digits));
                e.lp(n.unit.as_bytes())?;
                e.u8(n.precision).u8(u8::from(n.signed));
            }
        }
        Ok(e.finish())
    }

    /// Check that `outcomes` is a legal attestation for this descriptor.
    pub fn check_outcomes(&self, outcomes: &[String]) -> Result<()> {
        match self {
            Descriptor::Enum { outcomes: allowed } => {
                if outcomes.len() != 1 || !allowed.contains(&outcomes[0]) {
                    return Err(Error::Rejected("outcome not in enum descriptor"));
                }
            }
            Descriptor::Binary { outcomes: allowed } => {
                if outcomes.len() != 1 || !allowed.contains(&outcomes[0]) {
                    return Err(Error::Rejected("outcome not in binary descriptor"));
                }
            }
            Descriptor::Numeric(n) => {
                if outcomes.len() != self.nonces_needed() {
                    return Err(Error::Rejected("wrong number of numeric outcomes"));
                }
                let digits = if n.signed {
                    if outcomes[0] != "+" && outcomes[0] != "-" {
                        return Err(Error::Rejected("bad sign outcome"));
                    }
                    &outcomes[1..]
                } else {
                    outcomes
                };
                for d in digits {
                    let ok = d.len() == 1
                        && DIGITS[..usize::from(n.base)].contains(&d.as_bytes()[0]);
                    if !ok {
                        return Err(Error::Rejected("bad digit outcome"));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Decompose an integer into digit outcomes exactly as legacy `attestNumeric` does for valid
/// input (`abs(value).toString(base).padStart(numDigits, "0")`, sign first when `signed`), but
/// with integer input: fractional / NaN values and negative values for unsigned events are errors.
pub fn decompose_numeric(value: i64, n: &NumericDescriptor) -> Result<Vec<String>> {
    if !(2..=36).contains(&n.base) {
        return Err(Error::Malformed("numeric base"));
    }
    if !n.signed && value < 0 {
        return Err(Error::Rejected("negative value for unsigned event"));
    }
    let mut mag = value.unsigned_abs();
    let base = u64::from(n.base);
    let mut rev = Vec::new();
    if mag == 0 {
        rev.push(b'0');
    }
    while mag > 0 {
        rev.push(DIGITS[(mag % base) as usize]);
        mag /= base;
    }
    if rev.len() > usize::from(n.num_digits) {
        return Err(Error::Rejected("value exceeds digit capacity"));
    }
    let mut out = Vec::with_capacity(usize::from(n.num_digits) + 1);
    if n.signed {
        out.push(if value >= 0 { "+" } else { "-" }.to_string());
    }
    for _ in rev.len()..usize::from(n.num_digits) {
        out.push("0".to_string());
    }
    for b in rev.iter().rev() {
        out.push((*b as char).to_string());
    }
    Ok(out)
}

/// Oracle pre-commitment to an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announcement {
    /// Event id.
    pub event_id: String,
    /// Oracle key (x-only).
    pub oracle_pubkey: [u8; 32],
    /// Descriptor.
    pub descriptor: Descriptor,
    /// Maturity (unix seconds).
    pub maturity_time: u64,
    /// Announced nonce points R_i (x-only), one per outcome index.
    pub nonce_points: Vec<[u8; 32]>,
    /// BIP-340 signature of the oracle over [`Announcement::digest`].
    pub signature: [u8; 64],
}

impl Announcement {
    /// Domain-separated digest of the announcement body.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut e = Enc::new();
        e.fixed32(&self.oracle_pubkey);
        e.lp(self.event_id.as_bytes())?;
        e.lp(&self.descriptor.encode()?)?;
        e.u64(self.maturity_time);
        e.u32(u32::try_from(self.nonce_points.len()).map_err(|_| Error::Overflow)?);
        for r in &self.nonce_points {
            e.fixed32(r);
        }
        Ok(tagged_hash(DOMAIN_ANNOUNCEMENT, &e.finish()))
    }

    /// Structural validation plus the oracle's signature.
    pub fn verify(&self) -> Result<()> {
        check_ident(&self.event_id, MAX_EVENT_ID_LEN, "event id")?;
        self.descriptor.validate()?;
        if self.nonce_points.len() != self.descriptor.nonces_needed() {
            return Err(Error::Malformed("announcement nonce count"));
        }
        let secp = Secp256k1::verification_only();
        let pk = XOnlyPublicKey::from_slice(&self.oracle_pubkey)
            .map_err(|_| Error::Malformed("oracle public key"))?;
        let sig = schnorr::Signature::from_slice(&self.signature)
            .map_err(|_| Error::Malformed("announcement signature"))?;
        let msg = Message::from_digest(self.digest()?);
        secp.verify_schnorr(&sig, &msg, &pk)
            .map_err(|_| Error::SignatureInvalid)
    }
}

/// Signed outcomes for an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// Event id.
    pub event_id: String,
    /// Oracle key.
    pub oracle_pubkey: [u8; 32],
    /// Outcomes, one per nonce index.
    pub outcomes: Vec<String>,
    /// One signature `R || s` per outcome.
    pub signatures: Vec<[u8; 64]>,
    /// Attestation time.
    pub attestation_time: u64,
}

/// The message digest signed for outcome `index` of an event: a tagged hash over the injective
/// encoding of `(oracle key, event id, announcement digest, index, announced R, outcome)`.
pub fn attestation_digest(
    oracle_pubkey: &[u8; 32],
    event_id: &str,
    announcement_digest: &[u8; 32],
    index: u32,
    r: &[u8; 32],
    outcome: &str,
) -> Result<[u8; 32]> {
    let mut e = Enc::new();
    e.fixed32(oracle_pubkey);
    e.lp(event_id.as_bytes())?;
    e.fixed32(announcement_digest);
    e.u32(index);
    e.fixed32(r);
    e.lp(outcome.as_bytes())?;
    Ok(tagged_hash(DOMAIN_ATTESTATION, &e.finish()))
}

/// R-binding predicate: the signature's nonce point equals the announced one.
pub fn r_binding_ok(announced_r: &[u8; 32], signature: &[u8; 64]) -> bool {
    signature[..32] == announced_r[..]
}

/// Proof that an attestation was checked against its announcement. Only [`verify_attestation`]
/// can create one, so loan logic can demand it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOutcome {
    oracle_pubkey: [u8; 32],
    event_id: String,
    outcomes: Vec<String>,
}

impl VerifiedOutcome {
    /// Oracle key.
    pub fn oracle_pubkey(&self) -> &[u8; 32] {
        &self.oracle_pubkey
    }
    /// Event id.
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    /// All outcomes.
    pub fn outcomes(&self) -> &[String] {
        &self.outcomes
    }
    /// The single outcome of a binary/enum event.
    pub fn outcome(&self) -> Option<&str> {
        if self.outcomes.len() == 1 {
            Some(&self.outcomes[0])
        } else {
            None
        }
    }
}

/// Verify an attestation against its announcement (legacy `verifyAttestation`, hardened).
pub fn verify_attestation(ann: &Announcement, att: &Attestation) -> Result<VerifiedOutcome> {
    ann.verify()?;
    if ann.oracle_pubkey != att.oracle_pubkey || ann.event_id != att.event_id {
        return Err(Error::Rejected("attestation is for a different event or oracle"));
    }
    ann.descriptor.check_outcomes(&att.outcomes)?;
    if att.signatures.len() != att.outcomes.len() || att.signatures.len() != ann.nonce_points.len()
    {
        return Err(Error::Malformed("signature count"));
    }
    let ann_digest = ann.digest()?;
    let secp = Secp256k1::verification_only();
    let pk = XOnlyPublicKey::from_slice(&ann.oracle_pubkey)
        .map_err(|_| Error::Malformed("oracle public key"))?;
    for (i, (outcome, sig_bytes)) in att.outcomes.iter().zip(&att.signatures).enumerate() {
        let index = u32::try_from(i).map_err(|_| Error::Overflow)?;
        let r = &ann.nonce_points[i];
        if !r_binding_ok(r, sig_bytes) {
            return Err(Error::RBindingMismatch { index });
        }
        let digest = attestation_digest(&ann.oracle_pubkey, &ann.event_id, &ann_digest, index, r, outcome)?;
        let sig = schnorr::Signature::from_slice(sig_bytes)
            .map_err(|_| Error::Malformed("signature"))?;
        secp.verify_schnorr(&sig, &Message::from_digest(digest), &pk)
            .map_err(|_| Error::SignatureInvalid)?;
    }
    Ok(VerifiedOutcome {
        oracle_pubkey: att.oracle_pubkey,
        event_id: att.event_id.clone(),
        outcomes: att.outcomes.clone(),
    })
}

/// The oracle: owns the (synthetic) key and the single-writer token of its store.
pub struct Oracle<S: Store> {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    sk: SecretKey,
    pk: [u8; 32],
    store: S,
    token: WriterToken,
}

fn crypto<E>(m: &'static str) -> impl FnOnce(E) -> Error {
    move |_| Error::Crypto(m)
}

impl<S: Store> Oracle<S> {
    /// Create an oracle and become the single writer of `store`.
    pub fn new(mut store: S, secret: [u8; 32], writer_id: &str) -> Result<Self> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret).map_err(crypto("secret key"))?;
        let pk = Keypair::from_secret_key(&secp, &sk)
            .x_only_public_key()
            .0
            .serialize();
        let token = store.acquire_writer(writer_id)?;
        Ok(Oracle {
            secp,
            sk,
            pk,
            store,
            token,
        })
    }

    /// Oracle x-only public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.pk
    }

    /// Read access to the store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Mutable access to the store (tests, failure injection).
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    fn nonce(&self, event_id: &str, index: u32) -> Result<(SecretKey, [u8; 32])> {
        let mut e = Enc::new();
        e.fixed32(&self.sk.secret_bytes());
        e.lp(event_id.as_bytes())?;
        e.u32(index);
        let h = tagged_hash(DOMAIN_NONCE, &e.finish());
        let k = SecretKey::from_slice(&h).map_err(crypto("nonce out of range"))?;
        let (rx, parity) = PublicKey::from_secret_key(&self.secp, &k).x_only_public_key();
        let k = if parity == Parity::Odd { k.negate() } else { k };
        Ok((k, rx.serialize()))
    }

    /// `s = k + e*d` with BIP-340 parity normalisation; returns `R || s`.
    fn sign_with_nonce(&self, k: &SecretKey, r: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 64]> {
        let (px, parity) = PublicKey::from_secret_key(&self.secp, &self.sk).x_only_public_key();
        let d = if parity == Parity::Odd {
            self.sk.negate()
        } else {
            self.sk
        };
        let mut c = Vec::with_capacity(96);
        c.extend_from_slice(r);
        c.extend_from_slice(&px.serialize());
        c.extend_from_slice(digest);
        let e = Scalar::from_be_bytes(tagged_hash("BIP0340/challenge", &c))
            .map_err(crypto("challenge out of range"))?;
        let ed = d.mul_tweak(&e).map_err(crypto("challenge multiplication"))?;
        let s = k
            .add_tweak(&Scalar::from(ed))
            .map_err(crypto("response addition"))?;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(r);
        sig[32..].copy_from_slice(&s.secret_bytes());
        Ok(sig)
    }

    /// Create, sign and persist an announcement. Nonce points are reserved (`Fresh`) in the store.
    pub fn announce(
        &mut self,
        event_id: &str,
        descriptor: Descriptor,
        maturity_time: u64,
    ) -> Result<Announcement> {
        check_ident(event_id, MAX_EVENT_ID_LEN, "event id")?;
        descriptor.validate()?;
        let n = descriptor.nonces_needed();
        let mut nonce_points = Vec::with_capacity(n);
        for i in 0..n {
            let (_, r) = self.nonce(event_id, u32::try_from(i).map_err(|_| Error::Overflow)?)?;
            nonce_points.push(r);
        }
        let mut ann = Announcement {
            event_id: event_id.to_string(),
            oracle_pubkey: self.pk,
            descriptor,
            maturity_time,
            nonce_points,
            signature: [0u8; 64],
        };
        let digest = ann.digest()?;
        let kp = Keypair::from_secret_key(&self.secp, &self.sk);
        let sig = self
            .secp
            .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp);
        ann.signature = *sig.as_ref();
        ann.verify()?;
        self.store.reserve_announcement(
            &self.token,
            EventAnnouncementRecord {
                announcement: ann.clone(),
                announcement_hash: digest,
                attestation_id: None,
            },
        )?;
        Ok(ann)
    }

    /// Attest the given outcomes of an announced event.
    ///
    /// Order of operations: validate everything, **persist the nonce uses**, sign, self-verify,
    /// persist the attestation. A failure after the persist step leaves the nonces burned; there is
    /// no retry that could sign a second message with the same nonce.
    pub fn attest(&mut self, event_id: &str, outcomes: Vec<String>, now: u64) -> Result<Attestation> {
        let rec = self
            .store
            .get_announcement(event_id)?
            .ok_or(Error::NotFound("announcement"))?;
        if rec.attestation_id.is_some() {
            return Err(Error::NonceReused {
                event_id: event_id.to_string(),
                index: 0,
            });
        }
        let ann = rec.announcement;
        if now < ann.maturity_time {
            return Err(Error::NotMatured);
        }
        ann.descriptor.check_outcomes(&outcomes)?;
        let ann_digest = rec.announcement_hash;
        let mut uses = Vec::with_capacity(outcomes.len());
        for (i, o) in outcomes.iter().enumerate() {
            let index = u32::try_from(i).map_err(|_| Error::Overflow)?;
            let r = ann.nonce_points[i];
            let digest =
                attestation_digest(&self.pk, event_id, &ann_digest, index, &r, o)?;
            uses.push(NonceUse { index, r, digest });
        }
        // persist-before-sign
        self.store.begin_use(&self.token, event_id, &uses)?;
        let mut signatures = Vec::with_capacity(uses.len());
        for u in &uses {
            let (k, r) = self.nonce(event_id, u.index)?;
            if r != u.r {
                return Err(Error::RBindingMismatch { index: u.index });
            }
            signatures.push(self.sign_with_nonce(&k, &r, &u.digest)?);
        }
        let att = Attestation {
            event_id: event_id.to_string(),
            oracle_pubkey: self.pk,
            outcomes,
            signatures,
            attestation_time: now,
        };
        verify_attestation(&ann, &att)?;
        self.store.record_attestation(
            &self.token,
            AttestationRecord {
                attestation_id: attestation_id(event_id),
                event_id: event_id.to_string(),
                oracle_pubkey: self.pk,
                outcomes: att.outcomes.clone(),
                signatures: att.signatures.clone(),
                attestation_time: now,
                verified: true,
            },
        )?;
        Ok(att)
    }

    /// Attest a numeric event value.
    pub fn attest_numeric(&mut self, event_id: &str, value: i64, now: u64) -> Result<Attestation> {
        let rec = self
            .store
            .get_announcement(event_id)?
            .ok_or(Error::NotFound("announcement"))?;
        match &rec.announcement.descriptor {
            Descriptor::Numeric(n) => {
                let outcomes = decompose_numeric(value, n)?;
                self.attest(event_id, outcomes, now)
            }
            _ => Err(Error::Rejected("announcement is not numeric")),
        }
    }

    /// Attest a binary event (`true` = first label).
    pub fn attest_binary(&mut self, event_id: &str, outcome: bool, now: u64) -> Result<Attestation> {
        let rec = self
            .store
            .get_announcement(event_id)?
            .ok_or(Error::NotFound("announcement"))?;
        match &rec.announcement.descriptor {
            Descriptor::Binary { outcomes } => {
                let label = if outcome { &outcomes[0] } else { &outcomes[1] };
                self.attest(event_id, vec![label.clone()], now)
            }
            _ => Err(Error::Rejected("announcement is not binary")),
        }
    }

    /// Attest an enum event by outcome index.
    pub fn attest_enum(&mut self, event_id: &str, index: usize, now: u64) -> Result<Attestation> {
        let rec = self
            .store
            .get_announcement(event_id)?
            .ok_or(Error::NotFound("announcement"))?;
        match &rec.announcement.descriptor {
            Descriptor::Enum { outcomes } => {
                let label = outcomes
                    .get(index)
                    .ok_or(Error::Rejected("invalid outcome index"))?;
                self.attest(event_id, vec![label.clone()], now)
            }
            _ => Err(Error::Rejected("announcement is not enum")),
        }
    }
}

/// Attestation id of an event (one attestation per event).
pub fn attestation_id(event_id: &str) -> String {
    format!("att:{event_id}")
}
