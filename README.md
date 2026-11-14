# Payband

**Find out if you are underpaid, without anyone revealing their salary.**

Each person's salary is encrypted in their own browser to a model running in an attested
enclave on NEAR AI Cloud. The ciphertexts are stored on NEAR. When the round closes, all of
them go to the model in one sealed request, and only pay bands come out: 25th percentile,
median and 75th percentile per role, and only for groups of at least four. A NEAR contract
refuses the result unless the model's signature checks out and no submission was left out.

Built at NEAR HACKATHON (Nov 2026). Track: **Privacy & Private AI**.

- Live page: https://aditya-galaxy.github.io/payband/
- Contract (testnet): [`payband.testnet`](https://testnet.nearblocks.io/address/payband.testnet)
- Model: `deepseek-ai/DeepSeek-V4.1-Flash-1017`, served by NEAR AI in a TEE on [NEAR AI Cloud](https://cloud.near.ai), end-to-end encrypted (protocol v2), reasoning off

> Same author, separate and independent project in this hackathon (disclosed per rule Q-015):
> [Sureplate](https://github.com/Aditya-galaxy/sureplate), a device-warranty NFT.

## The problem

Pay transparency helps the people who are underpaid most, and they are the ones least
willing to share their number. Salary surveys either trust a company (HR, a survey vendor)
with everyone's raw salary, or rely on anonymous self-reporting that anyone can game.

## Who sees what

| Party | Sees |
| --- | --- |
| Your employer, the round's organiser, the person who runs the aggregation, this project | Your role, the fact that you took part, ciphertext. Never your salary. |
| NEAR AI Cloud's gateway | Ciphertext only. Every message, including the instructions, is encrypted to the model's key. |
| The model inside the TEE | Every salary, for the length of one request. Its key is bound to an Intel TDX + NVIDIA attestation. |
| Everyone, after the round | The bands, the exact signed request and reply, and the throwaway key the reply was encrypted to. |

## How it works

1. **Open a round.** `create_round` records the roles, the member accounts, `k_min` (at least 3;
   the demo uses 4), the model id and the model's ed25519 key. The key is taken from a NEAR AI
   attestation report fetched with a fresh nonce (`scripts/open-round.mjs`).
2. **Submit.** In the browser, the page fetches the attestation again (fresh nonce), confirms the
   round's key is still attested, then encrypts `{"role","salary_usd"}` to it
   (X25519 + HKDF-SHA256 + XChaCha20-Poly1305, NEAR AI's E2EE v2) and calls `submit`. Members
   may replace their submission until the deadline. Roles are public so the contract can count
   groups.
3. **Aggregate.** After the deadline, `scripts/aggregate.mjs` builds one chat request: an
   encrypted instruction, every on-chain ciphertext verbatim, an encrypted "go". The reply is
   encrypted to a throwaway client key. Reasoning is switched off, because a chain of thought would
   contain individual salaries and the reply is made public. The script decrypts the reply, refuses to publish anything that
   is not exactly `{"bands":[...]}` or that contains any number other than the bands, and fetches
   the model's signature over `model:sha256(request):sha256(response)`.
4. **Publish.** `publish` re-checks on chain: the request contains every stored ciphertext; it is
   for the round's model; the ed25519 signature verifies under the round's key
   (`env::ed25519_verify`); every band covers at least `k_min` people and its count matches the
   on-chain count; smaller groups get no band. The throwaway key is stored with it.
5. **Verify.** On the page, *Run the checks* recomputes both hashes, confirms every ciphertext
   is in the request, verifies the signature, decrypts the signed reply with the published key
   and compares it with the bands, and re-fetches the attestation. All in the browser.

## Why NEAR

- **NEAR AI Cloud** gives a model whose key lives in a TEE and whose replies are signed, with an
  OpenAI-compatible API and end-to-end encryption. That is what makes "encrypt to the model"
  possible from a plain web page.
- **The contract verifies the enclave, not the operator.** NEAR exposes `ed25519_verify` and
  `sha256` to contracts cheaply, so the chain itself checks the model's signature and that the
  request contained every submission. Anyone can publish; only a correct result is accepted.
- **Access keys limited to one method** let a member sign in with a key that can only call
  `submit`, so submitting is one click without handing the page their account.

## Try it

### 1. Look (30 seconds)

Open https://aditya-galaxy.github.io/payband/ . It opens round `acme-demo-11141825`, the one in
the demo video: nine encrypted submissions (four Engineer L2, four Engineer L3, one Staff
Engineer), published bands for the two groups of four, and Staff Engineer marked as never
published. Press **Run the checks**: six lines turn green (both hashes, all 9 ciphertexts in the
request, the enclave signature, the decrypted reply equals the bands, the key is attested now).
Type a salary into *Where do you stand?* (it stays in the browser) to see your marker on the band.

Transactions from that round: [open](https://testnet.nearblocks.io/txns/43MBgWzZaB5xeVyZ17vQiD7rQxUwujzUAoeE7TtL1cb7),
[publish, with the on-chain signature check](https://testnet.nearblocks.io/txns/9Gk9TqLXD6DGg6JjX1asFTCqz9dAYYjHwz4wwit1SQQn).
Every submission is listed on the [contract's page](https://testnet.nearblocks.io/address/payband.testnet).

### 2. Run the tests (1 minute)

```sh
cd contract && cargo test          # Rust 1.95+ (near-sdk 5.30)
```

`test result: ok. 13 passed`. The tests sign real ed25519 messages and cover: a valid result is
accepted and the small group suppressed; publishing early; dropping one submission; a signature
by another key; a tampered reply; a band for a group under `k_min`; a wrong count; a different
model; outsiders and late submissions.

### 3. Run a full round on testnet (about 8 minutes)

Needs `near-cli-rs`, Node 20+, the demo accounts (or your own; see the scripts) and a NEAR AI
Cloud API key in `.env` as `NEARAI_API_KEY=...`.

```sh
npm install
node scripts/open-round.mjs my-round 4        # pins the attested model key, open for 4 minutes
node scripts/submit-demo.mjs my-round         # nine members encrypt and submit
# wait until the round closes, then:
node scripts/aggregate.mjs my-round           # one sealed request, checks, publish
```

Open `https://aditya-galaxy.github.io/payband/?round=my-round` to watch it, then run the checks.

## Limits, stated plainly

- **Why this model.** In testing, GLM-5.3 Flash wrote individual salaries into its reasoning, and the
  publish step's leak check refused it, as designed. With reasoning off, GLM got quartiles wrong.
  DeepSeek V4.1 Flash with reasoning off was within $1k of exact on the demo data (one quartile
  rounded down by $1k).
- **The model does the arithmetic.** A language model can miscompute a percentile. The bands are
  checked against the model's signed reply, not recomputed. A deterministic aggregation program in
  an attested enclave is the obvious next step.
- **Attestation.** The page and scripts check that the round's key appears in a fresh,
  nonce-bound attestation report. Full verification of the Intel TDX and NVIDIA quotes is left to
  NEAR AI's verifier ([cloud.near.ai/verify](https://cloud.near.ai/verify)); it is not
  reimplemented here.
- **Self-reported numbers.** Anyone on the member list can enter any salary. Payroll-signed
  salary proofs are future work.
- **Small groups leak.** k = 4 with three quartiles still narrows things down; real use needs
  larger groups or coarser bands. The contract enforces `k_min ≥ 3`.
- **Key lifetime.** Submissions are encrypted to one model key; if NEAR AI rotates it before the
  round is aggregated, those ciphertexts cannot be opened. Rounds should be short.
- **Prompt injection.** A member could put instructions inside their encrypted record. The prompt
  says to treat records as data, and the publish step refuses any reply that is not exactly
  bands, but a malicious record could still skew the result.
- Testnet only. Not audited. "Acme" and its salaries are made up.

## Layout

```
contract/src/lib.rs     rounds, encrypted submissions, publish with on-chain signature + coverage + k checks
contract/src/tests.rs   13 tests with real ed25519 signatures
docs/index.html         the page: sign-in, in-browser encryption, bands, in-browser verification
scripts/e2ee.mjs        NEAR AI E2EE v2 encryption and attestation fetch (Node)
scripts/open-round.mjs, submit-demo.mjs, aggregate.mjs, near.mjs
video/                  record.mjs (real browser + testnet + NEAR AI), voice.sh (Google Cloud TTS, Chirp 3 HD)
```

## Disclosures

- All code was written during the hackathon (first commit 14 Nov 2026), with an AI coding agent
  (Claude Code), and run by the author.
- Libraries: `near-sdk` 5.30, `hex`; `@noble/curves`, `@noble/hashes`, `@noble/ciphers` (also in
  the browser via esm.sh); `near-api-js` 4.0.4 (vendored, unmodified); NEAR Connect 0.12.0.
- The E2EE format and attestation fields follow NEAR AI Cloud's public documentation.

## License

MIT
