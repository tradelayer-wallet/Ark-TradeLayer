//! Ark <-> TradeLayer VTXO handshake: template canonicity, deposit recognition, exit recognition
//! and the `ARK_WRAP_MINT` / redeem message flow as a state machine.
//!
//! Source: `tl-vtxo-handshake-optimized/ark-tradelayer-handshake.js` (the two copies in the
//! legacy tree are byte-identical) and `tradelayer-dlc-vtxo-validation-v2.js`. The validation file
//! `require`s `./arkTradeLayerHandshake.js` (the real file is `ark-tradelayer-handshake.js`) and
//! the TradeLayer `property`/`tally`/`txUtils` modules, none of which are in the repository, so the
//! balance/property bookkeeping is out of scope and chain access is the [`ChainView`] trait.
//!
//! Repaired defects (see README): placeholder Taproot key derivation, plain-SHA256 merkle path with
//! a throwing `compactSize`, trailing-byte tolerant script decoding, overwriting output-key index,
//! `vout 0` treated as missing, no double-mint protection, caller-supplied template on burn,
//! unconfirmed exit accepted, order-ambiguous template ids, float satoshi math.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{ControlBlock, TapNodeHash, TaprootSpendInfo};
use bitcoin::{ScriptBuf, Txid};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::hash::{tagged_hash, Enc};
use crate::legacy::canonical_json;
use crate::util::{check_ident, from_hex, hex32, to_hex};

/// Max registered templates.
pub const MAX_TEMPLATES: usize = 1024;
/// Max leaves per template.
pub const MAX_LEAVES: usize = 64;
/// Max bytes of one leaf script.
pub const MAX_SCRIPT_LEN: usize = 10_000;
/// Max witness stack items inspected.
pub const MAX_WITNESS_ITEMS: usize = 1000;
/// Max inputs/outputs inspected per transaction.
pub const MAX_TX_IO: usize = 10_000;
/// Legacy deposit confirmation requirement.
pub const DEFAULT_MIN_CONFIRMATIONS: u32 = 6;
/// Legacy `FEE_TOLERANCE` in `validateDLCVTXOBurn`.
pub const FEE_TOLERANCE_SATS: u64 = 10_000;
/// Legacy template id domain prefix.
pub const LEGACY_TEMPLATE_PREFIX: &str = "TL_ARK_TEMPLATE_V1";
/// v2 template id tag.
pub const TAG_TEMPLATE_V2: &str = "TL/ark-dlc/template/v2";
/// The role name of the unilateral user exit leaf.
pub const ROLE_USER_EXIT: &str = "user-exit";

const NETWORKS: [&str; 4] = [
    "bitcoin-mainnet",
    "bitcoin-testnet",
    "bitcoin-signet",
    "bitcoin-regtest",
];

/// An Ark VTXO template (leaf scripts as hex strings).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArkTemplate {
    /// Template version.
    pub version: u32,
    /// Network label.
    pub network: String,
    /// Internal key (hex).
    pub internal_key: String,
    /// Script tree merkle root (hex).
    pub merkle_root: String,
    /// Leaf scripts (hex).
    pub leaf_scripts: Vec<String>,
    /// Leaf versions.
    pub leaf_versions: Vec<u8>,
    /// Leaf roles, parallel to `leaf_scripts`.
    pub leaf_roles: Vec<String>,
    /// Timeouts object.
    pub timeouts: Value,
    /// Semantics object.
    pub semantics: Value,
    /// Declared Taproot output key (hex); required for registration.
    pub taproot_output_key: Option<String>,
    /// Declared template id (hex); must equal the computed id if present.
    pub template_id: Option<String>,
}

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Legacy `computeTemplateId`, byte-exact for integer-only `timeouts`/`semantics`:
/// `sha256("TL_ARK_TEMPLATE_V1" || network || internalKey || merkleRoot || JSON({sorted leafScripts, leafVersions, leafRoles, timeouts, semantics}))`.
///
/// DEFECTS (hence not used for registration): `leafScripts` is sorted independently of
/// `leafRoles`/`leafVersions`, so two templates that pair scripts and roles differently share an id;
/// `version` is not hashed; variable-length fields are not delimited.
pub fn template_id_legacy(t: &ArkTemplate) -> Result<String> {
    let mut scripts = t.leaf_scripts.clone();
    scripts.sort_by(|a, b| utf16_cmp(a, b));
    let j = |v: &Value| v.to_string();
    let body = format!(
        "{{\"leafScripts\":{},\"leafVersions\":{},\"leafRoles\":{},\"timeouts\":{},\"semantics\":{}}}",
        j(&Value::from(scripts)),
        j(&Value::from(t.leaf_versions.clone())),
        j(&Value::from(t.leaf_roles.clone())),
        j(&canonical_json(&t.timeouts)),
        j(&canonical_json(&t.semantics)),
    );
    let mut bytes = Vec::new();
    bytes.extend_from_slice(LEGACY_TEMPLATE_PREFIX.as_bytes());
    bytes.extend_from_slice(t.network.as_bytes());
    bytes.extend_from_slice(&from_hex(&t.internal_key)?);
    bytes.extend_from_slice(&from_hex(&t.merkle_root)?);
    bytes.extend_from_slice(body.as_bytes());
    Ok(to_hex(&crate::hash::sha256_bytes(&bytes)))
}

fn reject_floats(v: &Value, depth: usize) -> Result<()> {
    if depth > 8 {
        return Err(Error::TooLarge("template json depth"));
    }
    match v {
        Value::Number(n) if !(n.is_u64() || n.is_i64()) => {
            Err(Error::Malformed("non-integer number in template json"))
        }
        Value::Array(a) => a.iter().try_for_each(|x| reject_floats(x, depth + 1)),
        Value::Object(m) => m.values().try_for_each(|x| reject_floats(x, depth + 1)),
        _ => Ok(()),
    }
}

fn leaf_triples(t: &ArkTemplate) -> Result<Vec<(Vec<u8>, u8, String)>> {
    let mut v = Vec::new();
    for ((s, ver), role) in t.leaf_scripts.iter().zip(&t.leaf_versions).zip(&t.leaf_roles) {
        v.push((from_hex(s)?, *ver, role.clone()));
    }
    v.sort();
    Ok(v)
}

/// Structural validation of a template (everything except the Taproot commitment).
pub fn validate_template(t: &ArkTemplate) -> Result<()> {
    if t.version != 1 {
        return Err(Error::Rejected("unsupported template version"));
    }
    if !NETWORKS.contains(&t.network.as_str()) {
        return Err(Error::Rejected("unknown template network"));
    }
    XOnlyPublicKey::from_slice(&hex32(&t.internal_key)?)
        .map_err(|_| Error::Malformed("internal key is not an x-only point"))?;
    hex32(&t.merkle_root)?;
    let n = t.leaf_scripts.len();
    if n == 0 || n > MAX_LEAVES {
        return Err(Error::TooLarge("leaf count"));
    }
    if t.leaf_versions.len() != n || t.leaf_roles.len() != n {
        return Err(Error::Malformed("leaf arrays differ in length"));
    }
    for (i, s) in t.leaf_scripts.iter().enumerate() {
        let b = from_hex(s)?;
        if b.is_empty() || b.len() > MAX_SCRIPT_LEN {
            return Err(Error::TooLarge("leaf script"));
        }
        if t.leaf_versions[i] & 1 != 0 {
            return Err(Error::Malformed("odd leaf version"));
        }
        check_ident(&t.leaf_roles[i], 64, "leaf role")?;
        if t.leaf_roles[..i].contains(&t.leaf_roles[i]) {
            return Err(Error::Duplicate("leaf role"));
        }
    }
    for v in [&t.timeouts, &t.semantics] {
        if !v.is_object() {
            return Err(Error::Malformed("timeouts/semantics must be objects"));
        }
        reject_floats(v, 0)?;
    }
    Ok(())
}

/// Order-independent, role-bound, delimited template id (versioned replacement of the legacy id).
pub fn template_id_v2(t: &ArkTemplate) -> Result<String> {
    validate_template(t)?;
    let mut e = Enc::new();
    e.u32(t.version);
    e.lp(t.network.as_bytes())?;
    e.fixed32(&hex32(&t.internal_key)?);
    e.fixed32(&hex32(&t.merkle_root)?);
    let triples = leaf_triples(t)?;
    e.u32(triples.len() as u32);
    for (script, ver, role) in &triples {
        e.u8(*ver);
        e.lp(script)?;
        e.lp(role.as_bytes())?;
    }
    e.lp(canonical_json(&t.timeouts).to_string().as_bytes())?;
    e.lp(canonical_json(&t.semantics).to_string().as_bytes())?;
    Ok(to_hex(&tagged_hash(TAG_TEMPLATE_V2, &e.finish())))
}

/// BIP-341 output key `Q = P + H_TapTweak(P || root) G` (library arithmetic).
pub fn taproot_output_key(internal_key: &[u8; 32], merkle_root: &[u8; 32]) -> Result<[u8; 32]> {
    let secp = Secp256k1::verification_only();
    let internal = XOnlyPublicKey::from_slice(internal_key)
        .map_err(|_| Error::Malformed("internal key is not an x-only point"))?;
    use bitcoin::hashes::Hash;
    let info = TaprootSpendInfo::new_key_spend(
        &secp,
        internal,
        Some(TapNodeHash::from_byte_array(*merkle_root)),
    );
    Ok(info.output_key().to_x_only_public_key().serialize())
}

/// Strict witness-program decoding: exact length, `OP_0`/`OP_1..OP_16`, program 2..=40 bytes
/// (20 or 32 for v0). Legacy accepted trailing bytes.
pub fn decode_witness_program(spk: &[u8]) -> Result<(u8, &[u8])> {
    if spk.len() < 4 || spk.len() > 42 {
        return Err(Error::Malformed("not a witness program"));
    }
    let version = match spk[0] {
        0x00 => 0u8,
        v @ 0x51..=0x60 => v - 0x50,
        _ => return Err(Error::Malformed("not a witness program")),
    };
    let push = usize::from(spk[1]);
    if !(2..=40).contains(&push) || spk.len() != 2 + push {
        return Err(Error::Malformed("witness program length"));
    }
    if version == 0 && push != 20 && push != 32 {
        return Err(Error::Malformed("v0 program length"));
    }
    Ok((version, &spk[2..]))
}

/// Result of recognising an Ark commitment UTXO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    /// Template id.
    pub template_id: String,
    /// ASP id.
    pub asp_id: String,
    /// Taproot output key.
    pub taproot_output_key: [u8; 32],
    /// Value in satoshis.
    pub amount_sats: u64,
}

/// Governance-controlled registry of canonical templates.
#[derive(Default, Debug)]
pub struct TemplateRegistry {
    templates: BTreeMap<String, ArkTemplate>,
    output_key_index: BTreeMap<[u8; 32], (String, String)>,
    allowlist: BTreeSet<(String, String)>,
}

impl TemplateRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a template for an ASP after verifying its id and its real Taproot commitment.
    pub fn register(&mut self, mut t: ArkTemplate, asp_id: &str) -> Result<String> {
        check_ident(asp_id, 128, "asp id")?;
        let id = template_id_v2(&t)?;
        if let Some(d) = &t.template_id {
            if *d != id {
                return Err(Error::Rejected("declared template id does not match"));
            }
        }
        let declared = t
            .taproot_output_key
            .as_deref()
            .ok_or(Error::Rejected("taproot output key required"))?;
        let declared = hex32(declared)?;
        let computed = taproot_output_key(&hex32(&t.internal_key)?, &hex32(&t.merkle_root)?)?;
        if declared != computed {
            return Err(Error::Rejected("taproot output key mismatch"));
        }
        let pair = (id.clone(), asp_id.to_string());
        if let Some(existing) = self.output_key_index.get(&computed) {
            if *existing != pair {
                return Err(Error::Duplicate("output key already bound to another template/asp"));
            }
        } else if self.templates.len() >= MAX_TEMPLATES && !self.templates.contains_key(&id) {
            return Err(Error::Capacity("templates"));
        }
        t.template_id = Some(id.clone());
        self.templates.insert(id.clone(), t);
        self.output_key_index.insert(computed, pair.clone());
        self.allowlist.insert(pair);
        Ok(id)
    }

    /// Allowlist membership.
    pub fn is_allowed(&self, template_id: &str, asp_id: &str) -> bool {
        self.allowlist
            .contains(&(template_id.to_string(), asp_id.to_string()))
    }

    /// Template by id.
    pub fn get(&self, template_id: &str) -> Option<&ArkTemplate> {
        self.templates.get(template_id)
    }

    /// `(template id, asp id)` for an output key.
    pub fn find_by_output_key(&self, key: &[u8; 32]) -> Option<&(String, String)> {
        self.output_key_index.get(key)
    }

    /// Legacy `isArkCommitmentUtxo`: scriptPubKey must be a v1 32-byte program bound to an
    /// allowlisted `(template, asp)`.
    pub fn recognize_commitment(&self, script_pubkey: &[u8], value_sats: u64) -> Option<Commitment> {
        let (version, program) = decode_witness_program(script_pubkey).ok()?;
        if version != 1 || program.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(program);
        let (template_id, asp_id) = self.find_by_output_key(&key)?;
        if !self.is_allowed(template_id, asp_id) {
            return None;
        }
        Some(Commitment {
            template_id: template_id.clone(),
            asp_id: asp_id.clone(),
            taproot_output_key: key,
            amount_sats: value_sats,
        })
    }
}

/// Transaction output as seen on chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutView {
    /// Value (satoshis, integer).
    pub value_sats: u64,
    /// scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
}

/// Transaction input as seen on chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInView {
    /// Spent txid.
    pub prev_txid: Txid,
    /// Spent output index.
    pub prev_vout: u32,
    /// Witness stack.
    pub witness: Vec<Vec<u8>>,
}

/// Transaction view returned by the chain adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxView {
    /// Confirmations (0 = mempool).
    pub confirmations: u32,
    /// Inputs.
    pub inputs: Vec<TxInView>,
    /// Outputs.
    pub outputs: Vec<TxOutView>,
}

/// Chain access boundary (legacy `TxUtils.getRawTransaction` / `isUTXOUnspent`).
pub trait ChainView {
    /// Fetch a transaction.
    fn tx(&self, txid: &Txid) -> Result<Option<TxView>>;
    /// True if the output is unspent.
    fn is_unspent(&self, txid: &Txid, vout: u32) -> Result<bool>;
}

/// In-memory chain for tests.
#[derive(Default, Debug)]
pub struct MemoryChain {
    /// Known transactions.
    pub txs: BTreeMap<Txid, TxView>,
    /// Spent outpoints.
    pub spent: BTreeSet<(Txid, u32)>,
}

impl ChainView for MemoryChain {
    fn tx(&self, txid: &Txid) -> Result<Option<TxView>> {
        Ok(self.txs.get(txid).cloned())
    }
    fn is_unspent(&self, txid: &Txid, vout: u32) -> Result<bool> {
        Ok(!self.spent.contains(&(*txid, vout)))
    }
}

fn check_tx_bounds(tx: &TxView) -> Result<()> {
    if tx.inputs.len() > MAX_TX_IO || tx.outputs.len() > MAX_TX_IO {
        return Err(Error::TooLarge("transaction"));
    }
    if tx.inputs.iter().any(|i| i.witness.len() > MAX_WITNESS_ITEMS) {
        return Err(Error::TooLarge("witness"));
    }
    Ok(())
}

/// Result of a valid exit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitValidation {
    /// Template id.
    pub template_id: String,
    /// ASP id.
    pub asp_id: String,
    /// The user-exit leaf script used.
    pub leaf_script: Vec<u8>,
    /// Sum of all outputs of the spending transaction (legacy semantics, checked).
    pub released_value_sats: u64,
    /// Confirmations of the spending transaction.
    pub confirmations: u32,
}

/// Tokens that can be wrapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    /// `dlc-vtxo`
    DlcVtxo,
    /// `ark-vtxo`
    ArkVtxo,
}

impl TokenKind {
    /// Parse the wire `type` field (anything else is rejected).
    pub fn parse(s: &str) -> Result<TokenKind> {
        match s {
            "dlc-vtxo" => Ok(TokenKind::DlcVtxo),
            "ark-vtxo" => Ok(TokenKind::ArkVtxo),
            _ => Err(Error::Rejected("not a DLC/VTXO or ARK-VTXO token type")),
        }
    }
}

/// Choose the deposit vout from the two legacy field names. Legacy used
/// `params.fundingVout || params.depositVout`, which dropped a valid vout of 0.
pub fn pick_vout(funding_vout: Option<u32>, deposit_vout: Option<u32>) -> Result<u32> {
    match (funding_vout, deposit_vout) {
        (Some(a), Some(b)) if a != b => Err(Error::Rejected("conflicting vout fields")),
        (Some(a), _) => Ok(a),
        (None, Some(b)) => Ok(b),
        (None, None) => Err(Error::Rejected("deposit vout missing")),
    }
}

/// `ARK_WRAP_MINT` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintRequest {
    /// Token kind.
    pub token: TokenKind,
    /// Claimed template id.
    pub template_id: String,
    /// Claimed ASP.
    pub asp_id: String,
    /// Deposit txid.
    pub deposit_txid: Txid,
    /// Deposit vout.
    pub deposit_vout: u32,
    /// Amount (satoshis).
    pub value_sats: u64,
}

/// Redeem (burn) request. Template and ASP are taken from the recorded mint, not from the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedeemRequest {
    /// Deposit txid.
    pub deposit_txid: Txid,
    /// Deposit vout.
    pub deposit_vout: u32,
    /// Exit (redeem) transaction.
    pub redeem_txid: Txid,
    /// Amount being burned (must equal the minted amount).
    pub burn_amount_sats: u64,
}

/// Handshake messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// `ARK_WRAP_MINT`.
    WrapMint(MintRequest),
    /// Redeem/burn.
    Redeem(RedeemRequest),
}

/// Result of handling a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Mint accepted.
    Minted(Commitment),
    /// Redeem accepted.
    Redeemed {
        /// Value released by the exit transaction.
        released_value_sats: u64,
    },
}

/// Per-deposit protocol state. `Unseen` is the absence of an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepositState {
    /// Mint validated and recorded.
    Minted {
        /// Template.
        template_id: String,
        /// ASP.
        asp_id: String,
        /// Minted amount.
        amount_sats: u64,
    },
    /// Redeemed by an exit transaction (terminal).
    Burned {
        /// Exit transaction.
        redeem_txid: Txid,
    },
}

/// The bridge: registry + per-deposit state machine.
#[derive(Debug)]
pub struct Bridge {
    /// Template registry.
    pub registry: TemplateRegistry,
    min_confirmations: u32,
    deposits: BTreeMap<(Txid, u32), DepositState>,
}

impl Bridge {
    /// New bridge with the legacy 6-confirmation requirement.
    pub fn new(registry: TemplateRegistry) -> Self {
        Self::with_min_confirmations(registry, DEFAULT_MIN_CONFIRMATIONS)
    }

    /// New bridge with a custom confirmation requirement (at least 1).
    pub fn with_min_confirmations(registry: TemplateRegistry, min_confirmations: u32) -> Self {
        Bridge {
            registry,
            min_confirmations: min_confirmations.max(1),
            deposits: BTreeMap::new(),
        }
    }

    /// State of a deposit.
    pub fn state(&self, txid: &Txid, vout: u32) -> Option<&DepositState> {
        self.deposits.get(&(*txid, vout))
    }

    /// Handle one handshake message.
    pub fn handle<C: ChainView>(&mut self, chain: &C, msg: Message) -> Result<Outcome> {
        match msg {
            Message::WrapMint(m) => self.mint(chain, m),
            Message::Redeem(r) => self.redeem(chain, r),
        }
    }

    fn validate_deposit<C: ChainView>(
        &self,
        chain: &C,
        txid: &Txid,
        vout: u32,
        expected: u64,
    ) -> Result<Commitment> {
        let tx = chain
            .tx(txid)?
            .ok_or(Error::NotFound("deposit transaction"))?;
        check_tx_bounds(&tx)?;
        if tx.confirmations < self.min_confirmations {
            return Err(Error::Rejected("insufficient confirmations"));
        }
        let out = tx
            .outputs
            .get(vout as usize)
            .ok_or(Error::NotFound("deposit output"))?;
        let c = self
            .registry
            .recognize_commitment(&out.script_pubkey, out.value_sats)
            .ok_or(Error::Rejected("not a valid Ark commitment UTXO"))?;
        if out.value_sats != expected {
            return Err(Error::Rejected("amount mismatch"));
        }
        if !chain.is_unspent(txid, vout)? {
            return Err(Error::Rejected("UTXO already spent"));
        }
        Ok(c)
    }

    fn mint<C: ChainView>(&mut self, chain: &C, m: MintRequest) -> Result<Outcome> {
        if !self.registry.is_allowed(&m.template_id, &m.asp_id) {
            return Err(Error::Rejected("template not in allowlist"));
        }
        let key = (m.deposit_txid, m.deposit_vout);
        if self.deposits.contains_key(&key) {
            return Err(Error::Duplicate("deposit already minted"));
        }
        let c = self.validate_deposit(chain, &m.deposit_txid, m.deposit_vout, m.value_sats)?;
        if c.template_id != m.template_id || c.asp_id != m.asp_id {
            return Err(Error::Rejected("deposit template mismatch"));
        }
        self.deposits.insert(
            key,
            DepositState::Minted {
                template_id: c.template_id.clone(),
                asp_id: c.asp_id.clone(),
                amount_sats: c.amount_sats,
            },
        );
        Ok(Outcome::Minted(c))
    }

    fn redeem<C: ChainView>(&mut self, chain: &C, r: RedeemRequest) -> Result<Outcome> {
        let key = (r.deposit_txid, r.deposit_vout);
        let (template_id, asp_id, amount) = match self.deposits.get(&key) {
            Some(DepositState::Minted {
                template_id,
                asp_id,
                amount_sats,
            }) => (template_id.clone(), asp_id.clone(), *amount_sats),
            Some(DepositState::Burned { .. }) => {
                return Err(Error::Duplicate("deposit already redeemed"))
            }
            None => return Err(Error::NotFound("no recorded mint for this deposit")),
        };
        if !self.registry.is_allowed(&template_id, &asp_id) {
            return Err(Error::Rejected("template not in allowlist"));
        }
        // UNRESOLVED QUESTION: full redemption only. Legacy never relates the burn amount to the
        // minted amount; partial burns of one VTXO would orphan the remainder.
        if r.burn_amount_sats != amount {
            return Err(Error::Rejected("burn amount must equal minted amount"));
        }
        let exit = self.validate_exit(chain, &r.redeem_txid, &r.deposit_txid, r.deposit_vout)?;
        if exit.template_id != template_id || exit.asp_id != asp_id {
            return Err(Error::Rejected("exit template mismatch"));
        }
        if exit.released_value_sats.saturating_add(FEE_TOLERANCE_SATS) < r.burn_amount_sats {
            return Err(Error::Rejected("released value less than burn amount"));
        }
        self.deposits.insert(
            key,
            DepositState::Burned {
                redeem_txid: r.redeem_txid,
            },
        );
        Ok(Outcome::Redeemed {
            released_value_sats: exit.released_value_sats,
        })
    }

    /// Validate that `spending_txid` spends the deposit through the registered user-exit leaf.
    pub fn validate_exit<C: ChainView>(
        &self,
        chain: &C,
        spending_txid: &Txid,
        deposit_txid: &Txid,
        deposit_vout: u32,
    ) -> Result<ExitValidation> {
        let spend = chain
            .tx(spending_txid)?
            .ok_or(Error::NotFound("spending transaction"))?;
        check_tx_bounds(&spend)?;
        if spend.confirmations < self.min_confirmations {
            return Err(Error::Rejected("exit transaction not sufficiently confirmed"));
        }
        let input = spend
            .inputs
            .iter()
            .find(|i| i.prev_txid == *deposit_txid && i.prev_vout == deposit_vout)
            .ok_or(Error::Rejected("spending input not found"))?;
        let mut witness: &[Vec<u8>] = &input.witness;
        if witness.is_empty() {
            return Err(Error::Rejected("no witness data"));
        }
        // BIP-341 annex: last item starting with 0x50 when there are at least two items.
        if witness.len() >= 2 && witness[witness.len() - 1].first() == Some(&0x50) {
            witness = &witness[..witness.len() - 1];
        }
        if witness.len() == 1 {
            return Err(Error::Rejected("key-path spend (not a user exit)"));
        }
        let control = &witness[witness.len() - 1];
        let leaf = &witness[witness.len() - 2];

        // The prevout, not the witness, decides which template this is.
        let deposit_tx = chain
            .tx(deposit_txid)?
            .ok_or(Error::NotFound("deposit transaction"))?;
        check_tx_bounds(&deposit_tx)?;
        let prevout = deposit_tx
            .outputs
            .get(deposit_vout as usize)
            .ok_or(Error::NotFound("deposit output"))?;
        let commitment = self
            .registry
            .recognize_commitment(&prevout.script_pubkey, prevout.value_sats)
            .ok_or(Error::Rejected("prevout is not a known Ark commitment"))?;
        let template = self
            .registry
            .get(&commitment.template_id)
            .ok_or(Error::NotFound("template"))?;

        let cb = ControlBlock::decode(control)
            .map_err(|_| Error::Malformed("control block"))?;
        let secp = Secp256k1::verification_only();
        let output_key = XOnlyPublicKey::from_slice(&commitment.taproot_output_key)
            .map_err(|_| Error::Malformed("output key"))?;
        let script = ScriptBuf::from_bytes(leaf.clone());
        if !cb.verify_taproot_commitment(&secp, output_key, &script) {
            return Err(Error::Rejected("leaf and control block do not commit to the deposit key"));
        }
        if cb.internal_key.serialize() != hex32(&template.internal_key)? {
            return Err(Error::Rejected("control block internal key differs from template"));
        }

        let idx = template
            .leaf_roles
            .iter()
            .position(|r| r == ROLE_USER_EXIT)
            .ok_or(Error::Rejected("template has no user-exit leaf"))?;
        let expected = from_hex(&template.leaf_scripts[idx])?;
        if *leaf != expected || cb.leaf_version.to_consensus() != template.leaf_versions[idx] {
            return Err(Error::Rejected("leaf script is not a user-exit leaf"));
        }

        let mut released = 0u64;
        for o in &spend.outputs {
            released = released.checked_add(o.value_sats).ok_or(Error::Overflow)?;
        }
        Ok(ExitValidation {
            template_id: commitment.template_id,
            asp_id: commitment.asp_id,
            leaf_script: expected,
            released_value_sats: released,
            confirmations: spend.confirmations,
        })
    }
}
