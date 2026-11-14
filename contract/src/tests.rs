use super::*;
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;
use sha2::{Digest, Sha256};

const T0: u64 = 1_800_000_000;
const CLOSE: u64 = T0 + 1_000;
const MODEL: &str = "z-ai/glm-5.3-flash";

fn acc(s: &str) -> AccountId { s.parse().unwrap() }
fn at(who: &str, t: u64) {
    testing_env!(VMContextBuilder::new().predecessor_account_id(acc(who)).block_timestamp(t * 1_000_000_000).build());
}
fn key() -> SigningKey { SigningKey::from_bytes(&[7u8; 32]) }
fn ct(i: u8) -> String { hex::encode(vec![i; 32 + 24 + 30]) }
fn members() -> Vec<AccountId> { (1..=9).map(|i| acc(&format!("e{i}.testnet"))).collect() }

fn setup() -> Contract {
    at("org.testnet", T0);
    let mut c = Contract::new();
    c.create_round("r1".into(), "Acme 2026".into(), "USD".into(), vec!["L2".into(), "L3".into(), "Staff".into()],
        members(), 4, MODEL.into(), hex::encode(key().verifying_key().to_bytes()), CLOSE);
    // 4 x L2, 4 x L3, 1 x Staff
    for i in 1..=9u8 {
        let role = if i <= 4 { "L2" } else if i <= 8 { "L3" } else { "Staff" };
        at(&format!("e{i}.testnet"), T0 + 10);
        c.submit("r1".into(), role.into(), ct(i));
    }
    c
}

fn request_body(c: &Contract) -> String {
    let subs = c.get_submissions("r1".into());
    let msgs: Vec<String> = subs.iter().map(|s| format!("{{\"role\":\"user\",\"content\":\"{}\"}}", s.ciphertext)).collect();
    format!("{{\"model\":\"{MODEL}\",\"messages\":[{}],\"stream\":false}}", msgs.join(","))
}
fn sign(req: &str, resp: &str) -> String {
    let h = |s: &str| hex::encode(Sha256::digest(s.as_bytes()));
    hex::encode(key().sign(format!("{MODEL}:{}:{}", h(req), h(resp)).as_bytes()).to_bytes())
}
fn bands() -> Vec<Band> {
    vec![Band { role: "L2".into(), count: 4, p25: 100, median: 110, p75: 120 },
         Band { role: "L3".into(), count: 4, p25: 140, median: 150, p75: 165 }]
}
fn secret() -> String { hex::encode([9u8; 32]) }

#[test]
fn counts_and_status() {
    let c = setup();
    let r = c.get_round("r1".into()).unwrap();
    assert_eq!(r.counts, vec![("L2".into(), 4), ("L3".into(), 4), ("Staff".into(), 1)]);
    assert_eq!(r.status, "open");
    assert_eq!(r.submitted.len(), 9);
}

#[test]
fn resubmit_replaces() {
    let mut c = setup();
    at("e1.testnet", T0 + 20);
    c.submit("r1".into(), "L3".into(), ct(42));
    let r = c.get_round("r1".into()).unwrap();
    assert_eq!(r.counts[0].1, 3);
    assert_eq!(r.counts[1].1, 5);
    assert_eq!(c.get_submissions("r1".into()).len(), 9);
}

#[test]
#[should_panic(expected = "not a member")]
fn outsiders_cannot_submit() {
    let mut c = setup();
    at("mallory.testnet", T0 + 20);
    c.submit("r1".into(), "L2".into(), ct(1));
}

#[test]
#[should_panic(expected = "round is closed")]
fn no_late_submissions() {
    let mut c = setup();
    at("e1.testnet", CLOSE + 1);
    c.submit("r1".into(), "L2".into(), ct(1));
}

#[test]
fn valid_result_is_published_and_small_group_suppressed() {
    let mut c = setup();
    let req = request_body(&c);
    let resp = "{\"id\":\"chatcmpl-1\",\"choices\":[]}".to_string();
    at("anyone.testnet", CLOSE + 1);
    c.publish("r1".into(), bands(), req.clone(), resp.clone(), sign(&req, &resp), secret());
    let o = c.get_outcome("r1".into()).unwrap();
    assert_eq!(o.suppressed, vec!["Staff".to_string()]);
    assert_eq!(o.bands.len(), 2);
    assert_eq!(c.get_round("r1".into()).unwrap().status, "published");
}

#[test]
#[should_panic(expected = "round is still open")]
fn cannot_publish_early() {
    let mut c = setup();
    let req = request_body(&c);
    at("anyone.testnet", CLOSE);
    c.publish("r1".into(), bands(), req.clone(), "{}".into(), sign(&req, "{}"), secret());
}

#[test]
#[should_panic(expected = "request is missing a submission")]
fn dropping_a_submission_is_refused() {
    let mut c = setup();
    let full = request_body(&c);
    let dropped = full.replace(&format!(",{{\"role\":\"user\",\"content\":\"{}\"}}", ct(3)), "");
    at("anyone.testnet", CLOSE + 1);
    c.publish("r1".into(), bands(), dropped.clone(), "{}".into(), sign(&dropped, "{}"), secret());
}

#[test]
#[should_panic(expected = "signature does not verify")]
fn forged_signature_is_refused() {
    let mut c = setup();
    let req = request_body(&c);
    let other = SigningKey::from_bytes(&[8u8; 32]);
    let h = |s: &str| hex::encode(Sha256::digest(s.as_bytes()));
    let sig = hex::encode(other.sign(format!("{MODEL}:{}:{}", h(&req), h("{}")).as_bytes()).to_bytes());
    at("anyone.testnet", CLOSE + 1);
    c.publish("r1".into(), bands(), req, "{}".into(), sig, secret());
}

#[test]
#[should_panic(expected = "signature does not verify")]
fn tampered_response_is_refused() {
    let mut c = setup();
    let req = request_body(&c);
    let sig = sign(&req, "{\"real\":1}");
    at("anyone.testnet", CLOSE + 1);
    c.publish("r1".into(), bands(), req, "{\"fake\":1}".into(), sig, secret());
}

#[test]
#[should_panic(expected = "smaller than k_min")]
fn band_for_small_group_is_refused() {
    let mut c = setup();
    let req = request_body(&c);
    let mut b = bands();
    b.push(Band { role: "Staff".into(), count: 1, p25: 300, median: 300, p75: 300 });
    at("anyone.testnet", CLOSE + 1);
    c.publish("r1".into(), b, req.clone(), "{}".into(), sign(&req, "{}"), secret());
}

#[test]
#[should_panic(expected = "band count does not match")]
fn wrong_count_is_refused() {
    let mut c = setup();
    let req = request_body(&c);
    let mut b = bands();
    b[0].count = 5;
    at("anyone.testnet", CLOSE + 1);
    c.publish("r1".into(), b, req.clone(), "{}".into(), sign(&req, "{}"), secret());
}

#[test]
#[should_panic(expected = "different model")]
fn other_model_is_refused() {
    let mut c = setup();
    let req = request_body(&c).replace(MODEL, "cheap/model");
    at("anyone.testnet", CLOSE + 1);
    c.publish("r1".into(), bands(), req.clone(), "{}".into(), sign(&req, "{}"), secret());
}

#[test]
#[should_panic(expected = "k_min must be at least 3")]
fn k_min_floor() {
    at("org.testnet", T0);
    let mut c = Contract::new();
    c.create_round("r".into(), "t".into(), "USD".into(), vec!["a".into()], members(), 2, MODEL.into(), hex::encode([1u8; 32]), CLOSE);
}
