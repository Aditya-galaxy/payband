//! Payband: salary bands from encrypted submissions, computed inside an attested enclave.
//!
//! 1. An organiser opens a round: the roles, the people allowed to take part, the minimum
//!    group size `k_min`, and the public key of one NEAR AI Cloud model whose key lives in a
//!    TEE (checked against its attestation report before the round is opened).
//! 2. Each member encrypts `{role, salary}` in their browser to that model key and stores the
//!    ciphertext here. Nobody else, the organiser included, can open it.
//! 3. After the deadline, anyone with an API key sends every ciphertext to the model in one
//!    request. The model returns only bands. `publish` accepts the result only if:
//!    - the request body, parsed, is exactly: the round's model, no streaming, and the messages
//!      [the instruction pinned when the round opened] + [each stored ciphertext, once, as its
//!      own user message, in on-chain order], and nothing else,
//!    - the exact request body hashes to the hash the model signed,
//!    - the signature `"<model>:<request_hash>:<response_hash>"` verifies under the round's
//!      model key (ed25519, checked on chain),
//!    - every published band covers at least `k_min` people, matching the on-chain counts.
//!
//! The model's reply is end-to-end encrypted to a throwaway key; the publisher posts that key
//! so anyone can decrypt the signed reply and compare it with the published bands.

use near_sdk::store::LookupMap;
use near_sdk::{env, near, require, AccountId, BorshStorageKey, PanicOnDefault};

#[derive(BorshStorageKey)]
#[near]
enum Key {
    Rounds,
    /// v2 (exact request structure, pinned instruction) keeps its rounds under a new prefix.
    RoundsV2,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Submission {
    pub member: AccountId,
    pub role: String,
    /// hex of `[ephemeral x25519 pub (32)][nonce (24)][xchacha20poly1305 ciphertext+tag]`
    pub ciphertext: String,
    pub at: u64,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Band {
    pub role: String,
    pub count: u32,
    pub p25: u64,
    pub median: u64,
    pub p75: u64,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Outcome {
    pub bands: Vec<Band>,
    /// Roles with fewer than k_min submissions. Never given a band.
    pub suppressed: Vec<String>,
    pub request_body: String,
    pub request_hash: String,
    pub response_body: String,
    pub response_hash: String,
    pub signature: String,
    /// Throwaway ed25519 secret the reply was encrypted to (hex), published so anyone can decrypt it.
    pub client_secret: String,
    pub publisher: AccountId,
    pub published_at: u64,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Round {
    pub admin: AccountId,
    pub title: String,
    pub currency: String,
    pub roles: Vec<String>,
    pub members: Vec<AccountId>,
    pub k_min: u32,
    /// Canonical NEAR AI Cloud model id, e.g. "z-ai/glm-5.3-flash".
    pub model: String,
    /// The model's attested ed25519 key, hex. Members encrypt to it; its signature is checked.
    pub model_key: String,
    pub closes_at: u64,
    /// The aggregation instruction in plain text, fixed when the round opens.
    pub instruction: String,
    /// The same instruction encrypted to the model key. Publish requires exactly this ciphertext.
    pub instruction_ct: String,
    /// The ephemeral X25519 secret used for `instruction_ct`, so anyone can re-encrypt
    /// `instruction` and confirm the ciphertext says what the plain text says.
    pub instruction_eph: String,
    pub submissions: Vec<Submission>,
    pub outcome: Option<Outcome>,
}

#[near(serializers = [json])]
pub struct RoundView {
    pub round_id: String,
    pub admin: AccountId,
    pub title: String,
    pub currency: String,
    pub roles: Vec<String>,
    pub members: Vec<AccountId>,
    pub k_min: u32,
    pub model: String,
    pub model_key: String,
    pub closes_at: u64,
    pub instruction: String,
    pub instruction_ct: String,
    pub instruction_eph: String,
    pub counts: Vec<(String, u32)>,
    pub submitted: Vec<AccountId>,
    pub status: String,
    pub now: u64,
}

pub const MAX_MEMBERS: usize = 200;
pub const MAX_CIPHERTEXT_HEX: usize = 2_000;

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    rounds: LookupMap<String, Round>,
}

fn now_sec() -> u64 {
    env::block_timestamp() / 1_000_000_000
}

fn hex32(s: &str, what: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap_or_else(|_| env::panic_str(&format!("{what}: not hex")));
    v.try_into().unwrap_or_else(|_| env::panic_str(&format!("{what}: must be 32 bytes")))
}

fn emit(event: &str, data: near_sdk::serde_json::Value) {
    env::log_str(&format!(
        "EVENT_JSON:{}",
        near_sdk::serde_json::json!({"standard": "payband", "version": "1.0.0", "event": event, "data": [data]})
    ));
}

/// Fields a request may carry. Anything else (tools, response formats, extra settings) is refused.
const ALLOWED_FIELDS: [&str; 6] = ["model", "messages", "stream", "temperature", "chat_template_kwargs", "max_tokens"];

fn check_request(round: &Round, body: &str) {
    use near_sdk::serde_json::Value;
    let v: Value = near_sdk::serde_json::from_str(body).unwrap_or_else(|_| env::panic_str("request is not JSON"));
    let obj = v.as_object().unwrap_or_else(|| env::panic_str("request is not a JSON object"));
    require!(obj.keys().all(|k| ALLOWED_FIELDS.contains(&k.as_str())), "request has a field that is not allowed");
    require!(obj.get("model").and_then(Value::as_str) == Some(round.model.as_str()), "request is for a different model");
    require!(obj.get("stream").and_then(Value::as_bool) == Some(false), "request must not stream");
    let msgs = obj.get("messages").and_then(Value::as_array).unwrap_or_else(|| env::panic_str("request has no messages"));
    let is_msg = |m: &Value, role: &str, content: &str| {
        m.as_object().map_or(false, |o| o.len() == 2 && o.get("role").and_then(Value::as_str) == Some(role)
            && o.get("content").and_then(Value::as_str) == Some(content))
    };
    require!(msgs.len() == 1 + round.submissions.len(), "request must hold the instruction plus exactly one message per submission");
    require!(is_msg(&msgs[0], "system", &round.instruction_ct), "first message must be the round's pinned instruction");
    for (m, s) in msgs[1..].iter().zip(round.submissions.iter()) {
        require!(is_msg(m, "user", &s.ciphertext), "each submission must appear once, as its own user message, in on-chain order");
    }
}

impl Round {
    fn counts(&self) -> Vec<(String, u32)> {
        self.roles
            .iter()
            .map(|r| (r.clone(), self.submissions.iter().filter(|s| &s.role == r).count() as u32))
            .collect()
    }
}

#[near]
impl Contract {
    #[init]
    pub fn new() -> Self {
        Self { rounds: LookupMap::new(Key::RoundsV2) }
    }

    /// One-off upgrade from v1 on testnet: start over with an empty round table.
    #[private]
    #[init(ignore_state)]
    pub fn migrate_v2() -> Self {
        Self { rounds: LookupMap::new(Key::RoundsV2) }
    }

    /// Open a round. The caller becomes its admin.
    #[allow(clippy::too_many_arguments)]
    pub fn create_round(
        &mut self,
        round_id: String,
        title: String,
        currency: String,
        roles: Vec<String>,
        members: Vec<AccountId>,
        k_min: u32,
        model: String,
        model_key: String,
        closes_at: u64,
        instruction: String,
        instruction_ct: String,
        instruction_eph: String,
    ) {
        require!(!instruction.is_empty() && instruction.len() <= 4_000, "instruction: 1-4000 chars");
        require!(instruction_ct.len() >= 2 * (32 + 24 + 16 + 1) && instruction_ct.len() <= 10_000
            && instruction_ct.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "instruction_ct: lowercase hex");
        hex32(&instruction_eph, "instruction_eph");
        require!(!round_id.is_empty() && round_id.len() <= 64, "round_id: 1-64 chars");
        require!(!self.rounds.contains_key(&round_id), "round already exists");
        require!(!title.is_empty() && title.len() <= 120, "title: 1-120 chars");
        require!(!roles.is_empty() && roles.len() <= 20, "roles: 1-20");
        require!(roles.iter().all(|r| !r.is_empty() && r.len() <= 48), "role: 1-48 chars");
        require!(!members.is_empty() && members.len() <= MAX_MEMBERS, "members: 1-200");
        require!(k_min >= 3, "k_min must be at least 3");
        require!(!model.is_empty() && model.len() <= 100, "model: 1-100 chars");
        hex32(&model_key, "model_key");
        require!(closes_at > now_sec(), "closes_at must be in the future");
        let mut members = members;
        members.sort();
        members.dedup();
        emit("round_created", near_sdk::serde_json::json!({"round_id": round_id, "k_min": k_min, "model": model, "model_key": model_key}));
        self.rounds.insert(
            round_id,
            Round {
                admin: env::predecessor_account_id(),
                title,
                currency,
                roles,
                members,
                k_min,
                model,
                model_key: model_key.to_lowercase(),
                closes_at,
                instruction,
                instruction_ct,
                instruction_eph,
                submissions: vec![],
                outcome: None,
            },
        );
    }

    /// Store (or replace) the caller's encrypted submission. Only the round's members, only before
    /// the deadline. The role is public so the contract can count groups; the salary is not.
    pub fn submit(&mut self, round_id: String, role: String, ciphertext: String) {
        let now = now_sec();
        let member = env::predecessor_account_id();
        let round = self.rounds.get_mut(&round_id).expect("unknown round");
        require!(now <= round.closes_at, "round is closed");
        require!(round.members.binary_search(&member).is_ok(), "not a member of this round");
        require!(round.roles.contains(&role), "unknown role");
        require!(
            ciphertext.len() >= 2 * (32 + 24 + 16 + 1) && ciphertext.len() <= MAX_CIPHERTEXT_HEX,
            "ciphertext has the wrong size"
        );
        require!(ciphertext.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "ciphertext: lowercase hex");
        round.submissions.retain(|s| s.member != member);
        round.submissions.push(Submission { member: member.clone(), role: role.clone(), ciphertext, at: now });
        emit("submitted", near_sdk::serde_json::json!({"round_id": round_id, "member": member, "role": role}));
    }

    /// Publish the enclave's result. Anyone may call it after the deadline; the checks, not the
    /// caller, make it trustworthy.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        &mut self,
        round_id: String,
        bands: Vec<Band>,
        request_body: String,
        response_body: String,
        signature: String,
        client_secret: String,
    ) {
        let now = now_sec();
        let round = self.rounds.get_mut(&round_id).expect("unknown round");
        require!(now > round.closes_at, "round is still open");
        require!(round.outcome.is_none(), "already published");

        // 1. The request is exactly: pinned instruction + each submission once, in order.
        check_request(round, &request_body);

        // 2. The model's signature over model:request_hash:response_hash.
        let request_hash = hex::encode(env::sha256(request_body.as_bytes()));
        let response_hash = hex::encode(env::sha256(response_body.as_bytes()));
        let text = format!("{}:{}:{}", round.model, request_hash, response_hash);
        let sig: [u8; 64] = hex::decode(&signature)
            .ok()
            .and_then(|v| v.try_into().ok())
            .unwrap_or_else(|| env::panic_str("signature: 64 bytes hex"));
        let key = hex32(&round.model_key, "model_key");
        require!(env::ed25519_verify(&sig, text.as_bytes(), &key), "signature does not verify under the round's model key");
        hex32(&client_secret, "client_secret");

        // 3. Group-size rule, against on-chain counts.
        let counts = round.counts();
        let mut suppressed = vec![];
        for (role, n) in counts.iter() {
            let band = bands.iter().find(|b| &b.role == role);
            if *n < round.k_min {
                require!(band.is_none(), "a band was published for a group smaller than k_min");
                suppressed.push(role.clone());
            } else {
                let b = band.unwrap_or_else(|| env::panic_str("missing band for an eligible role"));
                require!(b.count == *n, "band count does not match the submissions on chain");
                require!(b.p25 <= b.median && b.median <= b.p75, "band is not ordered");
            }
        }
        require!(bands.iter().all(|b| round.roles.contains(&b.role)), "band for an unknown role");

        emit("published", near_sdk::serde_json::json!({"round_id": round_id, "request_hash": request_hash, "response_hash": response_hash}));
        round.outcome = Some(Outcome {
            bands,
            suppressed,
            request_body,
            request_hash,
            response_body,
            response_hash,
            signature,
            client_secret,
            publisher: env::predecessor_account_id(),
            published_at: now,
        });
    }

    // ───── views ─────

    pub fn get_round(&self, round_id: String) -> Option<RoundView> {
        let r = self.rounds.get(&round_id)?;
        let now = now_sec();
        Some(RoundView {
            round_id,
            admin: r.admin.clone(),
            title: r.title.clone(),
            currency: r.currency.clone(),
            roles: r.roles.clone(),
            members: r.members.clone(),
            k_min: r.k_min,
            model: r.model.clone(),
            model_key: r.model_key.clone(),
            closes_at: r.closes_at,
            instruction: r.instruction.clone(),
            instruction_ct: r.instruction_ct.clone(),
            instruction_eph: r.instruction_eph.clone(),
            counts: r.counts(),
            submitted: r.submissions.iter().map(|s| s.member.clone()).collect(),
            status: if r.outcome.is_some() { "published" } else if now > r.closes_at { "closed" } else { "open" }.to_string(),
            now,
        })
    }

    pub fn get_submissions(&self, round_id: String) -> Vec<Submission> {
        self.rounds.get(&round_id).map(|r| r.submissions.clone()).unwrap_or_default()
    }

    pub fn get_outcome(&self, round_id: String) -> Option<Outcome> {
        self.rounds.get(&round_id).and_then(|r| r.outcome.clone())
    }
}

#[cfg(test)]
mod tests;
