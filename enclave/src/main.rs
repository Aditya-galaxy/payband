//! Payband's aggregator, run by OutLayer inside an Intel TDX enclave and called only by the
//! Payband NEAR contract.
//!
//! Two operations, JSON on stdin, JSON on stdout:
//!
//! * `{"op":"pubkey","round_id":R}` → `{"pubkey":"<x25519 hex>"}`
//!   The round's private key is `mac("rounds", "payband:round:" + R)`: an HMAC under a key the
//!   OutLayer keystore derives inside the TEE for *this exact wasm* (`bind: "wasm"`) and *this
//!   caller* (`caller: "predecessor"`, i.e. the Payband contract). Nobody, including the authors,
//!   can compute it outside a run of this build called by that contract.
//!
//! * `{"op":"aggregate","round_id":R,"k_min":K,"records":[{"role":..,"ct":..}]}` →
//!   `{"bands":[{role,count,p25,median,p75}],"accepted":n,"rejected":m}`
//!   Re-derives the key, opens every record, and computes the 25th/50th/75th percentile per role
//!   with linear interpolation (numpy's default), rounded to the nearest 1000. Roles with fewer
//!   than K valid records get no band. No individual value is ever written out.
//!
//! Record format (hex): `[ephemeral x25519 public 32][nonce 24][XChaCha20-Poly1305 ciphertext+tag]`,
//! key = HKDF-SHA256(X25519 shared secret, info "payband-enclave-v1"), AAD = the round id, plaintext
//! `{"role": "...", "salary_usd": <integer>}`. A record that does not open, whose inner role differs
//! from its public role, or whose salary is out of range is counted as rejected and ignored.

use std::collections::BTreeMap;
use std::io::Read;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

wit_bindgen::generate!({ world: "encryption-keys-host", path: "wit/deps/encryption-keys.wit" });
use outlayer::encryption_keys::api as keys;

#[cfg(target_arch = "wasm32")]
#[used]
#[link_section = "outlayer.manifest"]
static OUTLAYER_MANIFEST: [u8; include_bytes!("../manifests/payband.json").len()] = *include_bytes!("../manifests/payband.json");

pub const INFO: &[u8] = b"payband-enclave-v1";

#[derive(Deserialize)]
struct Record { role: String, ct: String }
#[derive(Deserialize)]
struct Input { op: String, round_id: String, #[serde(default)] k_min: usize, #[serde(default)] records: Vec<Record> }
#[derive(Deserialize)]
struct Inner { role: String, salary_usd: u64 }

fn round_secret(round_id: &str) -> Result<StaticSecret, String> {
    let tag = keys::mac("rounds", None, format!("payband:round:{round_id}").as_bytes())?;
    let bytes: [u8; 32] = tag.try_into().map_err(|_| "mac is not 32 bytes".to_string())?;
    Ok(StaticSecret::from(bytes))
}

pub fn open(secret: &StaticSecret, round_id: &str, ct_hex: &str) -> Option<Vec<u8>> {
    let data = hex::decode(ct_hex).ok()?;
    if data.len() < 32 + 24 + 16 { return None; }
    let eph: [u8; 32] = data[..32].try_into().ok()?;
    let shared = secret.diffie_hellman(&PublicKey::from(eph));
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared.as_bytes()).expand(INFO, &mut key).ok()?;
    XChaCha20Poly1305::new((&key).into())
        .decrypt(XNonce::from_slice(&data[32..56]), Payload { msg: &data[56..], aad: round_id.as_bytes() })
        .ok()
}

/// numpy.percentile(..., method="linear") on a sorted slice.
pub fn percentile(sorted: &[u64], q: f64) -> f64 {
    let pos = q * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    sorted[lo] as f64 + (sorted[hi] as f64 - sorted[lo] as f64) * (pos - lo as f64)
}

pub fn round_1000(v: f64) -> u64 { ((v / 1000.0).round() as u64) * 1000 }

pub fn bands(groups: &BTreeMap<String, Vec<u64>>, k_min: usize) -> Vec<serde_json::Value> {
    groups.iter().filter(|(_, v)| v.len() >= k_min.max(1)).map(|(role, v)| {
        let mut s = v.clone(); s.sort_unstable();
        json!({"role": role, "count": s.len(), "p25": round_1000(percentile(&s, 0.25)),
               "median": round_1000(percentile(&s, 0.5)), "p75": round_1000(percentile(&s, 0.75))})
    }).collect()
}

fn run() -> Result<serde_json::Value, String> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let input: Input = serde_json::from_str(&raw).map_err(|e| format!("bad input: {e}"))?;
    let secret = round_secret(&input.round_id)?;
    match input.op.as_str() {
        "pubkey" => Ok(json!({"pubkey": hex::encode(PublicKey::from(&secret).as_bytes())})),
        "aggregate" => {
            if input.k_min < 3 { return Err("k_min must be at least 3".into()); }
            let mut groups: BTreeMap<String, Vec<u64>> = BTreeMap::new();
            let mut rejected = 0usize;
            for r in &input.records {
                let ok = open(&secret, &input.round_id, &r.ct)
                    .and_then(|pt| serde_json::from_slice::<Inner>(&pt).ok())
                    .filter(|i| i.role == r.role && i.salary_usd >= 1_000 && i.salary_usd <= 100_000_000);
                match ok { Some(i) => groups.entry(i.role).or_default().push(i.salary_usd), None => rejected += 1 }
            }
            let accepted = input.records.len() - rejected;
            Ok(json!({"bands": bands(&groups, input.k_min), "accepted": accepted, "rejected": rejected}))
        }
        other => Err(format!("unknown op {other}")),
    }
}

fn main() {
    let out = run().unwrap_or_else(|e| json!({"error": e}));
    print!("{out}");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numpy_linear_percentiles() {
        let s = [109_000, 112_000, 124_000, 131_000];
        assert_eq!(round_1000(percentile(&s, 0.25)), 111_000);
        assert_eq!(round_1000(percentile(&s, 0.5)), 118_000);
        assert_eq!(round_1000(percentile(&s, 0.75)), 126_000);
        let s = [147_000, 152_000, 159_000, 168_000];
        assert_eq!(round_1000(percentile(&s, 0.25)), 151_000);
    }
    #[test]
    fn open_roundtrip_and_aad() {
        use chacha20poly1305::aead::OsRng;
        let sk = StaticSecret::from([7u8; 32]);
        let pk = PublicKey::from(&sk);
        let eph = StaticSecret::random_from_rng(OsRng);
        let shared = eph.diffie_hellman(&pk);
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, shared.as_bytes()).expand(INFO, &mut key).unwrap();
        let nonce = [3u8; 24];
        let ct = XChaCha20Poly1305::new((&key).into()).encrypt(XNonce::from_slice(&nonce), Payload { msg: b"{\"role\":\"A\",\"salary_usd\":5000}", aad: b"r1" }).unwrap();
        let mut blob = PublicKey::from(&eph).as_bytes().to_vec(); blob.extend_from_slice(&nonce); blob.extend_from_slice(&ct);
        let h = hex::encode(blob);
        assert!(open(&sk, "r1", &h).is_some());
        assert!(open(&sk, "r2", &h).is_none(), "a record is bound to its round");
    }
    #[test]
    fn small_groups_get_no_band() {
        let mut g = BTreeMap::new();
        g.insert("A".to_string(), vec![1, 2, 3, 4]);
        g.insert("B".to_string(), vec![9]);
        let b = bands(&g, 4);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0]["role"], "A");
    }
}
