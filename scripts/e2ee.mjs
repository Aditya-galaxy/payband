// NEAR AI Cloud end-to-end encryption (protocol v2) and attestation helpers.
// Same code runs in Node (scripts) and, via esm.sh, in the browser page.
import { ed25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv, x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

export const API = 'https://cloud-api.near.ai';
const INFO = utf8ToBytes('ed25519_encryption');

/**
 * Encrypt to a model's ed25519 key: [ephemeral x25519 pub 32][nonce 24][ciphertext+tag], hex.
 * Pass `ephHex` (and the nonce is then taken from `nonceHex`) to make it reproducible: anyone holding
 * the ephemeral secret can re-encrypt the same text and get the same bytes. Used only for the public
 * round instruction, never for salaries.
 */
export function encryptFor(modelKeyHex, plaintext, ephHex, nonceHex) {
  const recipient = edwardsToMontgomeryPub(hexToBytes(modelKeyHex));
  const eph = ephHex ? hexToBytes(ephHex) : x25519.utils.randomPrivateKey();
  const key = hkdf(sha256, x25519.getSharedSecret(eph, recipient), undefined, INFO, 32);
  const nonce = nonceHex ? hexToBytes(nonceHex) : randomBytes(24);
  const ct = xchacha20poly1305(key, nonce).encrypt(utf8ToBytes(plaintext));
  const out = new Uint8Array(32 + 24 + ct.length);
  out.set(x25519.getPublicKey(eph), 0); out.set(nonce, 32); out.set(ct, 56);
  return bytesToHex(out);
}

/** Decrypt a hex field the model encrypted to our ed25519 client secret. */
export function decryptWith(clientSecretHex, dataHex) {
  const data = hexToBytes(dataHex);
  const sk = edwardsToMontgomeryPriv(hexToBytes(clientSecretHex));
  const key = hkdf(sha256, x25519.getSharedSecret(sk, data.slice(0, 32)), undefined, INFO, 32);
  return new TextDecoder().decode(xchacha20poly1305(key, data.slice(32, 56)).decrypt(data.slice(56)));
}

export function newClientKey() {
  const secret = ed25519.utils.randomPrivateKey();
  return { secret: bytesToHex(secret), pub: bytesToHex(ed25519.getPublicKey(secret)) };
}

export const randomHex = n => bytesToHex(randomBytes(n));
export const sha256hex = s => bytesToHex(sha256(typeof s === 'string' ? utf8ToBytes(s) : s));
export const verifySig = (sigHex, text, keyHex) => ed25519.verify(hexToBytes(sigHex), utf8ToBytes(text), hexToBytes(keyHex));

/**
 * Fetch the model's attestation candidates with a fresh nonce. Returns the candidates whose nonce
 * echoes ours and that carry an ed25519 key. Full Intel TDX + NVIDIA quote verification is done by
 * NEAR AI's verifier (cloud.near.ai/verify); this check binds the key to *this* request's report.
 */
export async function attestedKeys(model) {
  const nonce = bytesToHex(randomBytes(32));
  const q = new URLSearchParams({ model, provider: 'near', signing_algo: 'ed25519', include_tls_fingerprint: 'false', nonce });
  const r = await fetch(`${API}/v1/attestation/report?${q}`, { headers: { 'x-no-aliasing': 'true' } });
  if (!r.ok) throw new Error(`attestation ${r.status}`);
  const rep = await r.json();
  const ok = (rep.model_attestations || []).filter(m =>
    m.request_nonce === nonce && m.signing_algo === 'ed25519' && /^[0-9a-f]{64}$/.test(m.signing_public_key || '') && m.intel_quote);
  return { nonce, candidates: ok, report: rep };
}
