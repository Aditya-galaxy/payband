# Payband

**Find out if you are underpaid, without anyone revealing their salary.**

Each person's salary is encrypted in their own browser to a model running in an attested
enclave on NEAR AI Cloud. The ciphertexts are stored on NEAR. When the round closes, all of
them go to the model in one sealed request, and only pay bands come out: 25th percentile,
median and 75th percentile per role, and only for groups of at least four. A NEAR contract
refuses the result unless the model's signature checks out and the signed request was exactly the
instruction fixed when the round opened plus each submission once, nothing added or left out.

Built at NEAR HACKATHON (Nov 2026). Tracks: **Privacy & Private AI**, **Real-World Money**.

- Live page: https://aditya-galaxy.github.io/payband/
- Contract (testnet): [`payband.testnet`](https://testnet.nearblocks.io/address/payband.testnet)
- Model: `deepseek-ai/DeepSeek-V4.1-Flash-1017`, served by NEAR AI in a TEE on [NEAR AI Cloud](https://cloud.near.ai), end-to-end encrypted (protocol v2), reasoning off

> Same author, separate and independent project in this hackathon (disclosed per rule Q-015):
> [Sureplate](https://github.com/Aditya-galaxy/sureplate), a device-warranty NFT.

## The problem

Pay transparency helps the people who are underpaid most, and they are the ones least
willing to share their number. It is also becoming a legal duty: the EU Pay Transparency Directive
(Directive (EU) 2023/970, to be in national law by 7 June 2026) gives workers the right to ask
for average pay levels for people doing the same work. Payband is one way to answer that kind of
question without anyone, the employer included, handling individual salaries. Salary surveys either trust a company (HR, a survey vendor)
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
   the demo uses 4), the model id, the model's ed25519 key and the **aggregation instruction**.
   The key comes from a NEAR AI attestation report fetched with a fresh nonce. The instruction is
   stored three ways: plain text, encrypted to the model key, and the ephemeral secret used to
   encrypt it, so anyone can re-encrypt the text and confirm the ciphertext says exactly that
   (`scripts/open-round.mjs`).
2. **Submit.** In the browser, the page fetches the attestation again (fresh nonce), confirms the
   round's key is still attested, then encrypts `{"role","salary_usd"}` to it
   (X25519 + HKDF-SHA256 + XChaCha20-Poly1305, NEAR AI's E2EE v2) and calls `submit`. Members
   may replace their submission until the deadline. Roles are public so the contract can count
   groups.
3. **Aggregate.** After the deadline, `scripts/aggregate.mjs` sends one chat request: the pinned
   instruction ciphertext, then every on-chain ciphertext verbatim as its own user message. The
   reply is encrypted to a throwaway client key. Reasoning is switched off, because a chain of
   thought would contain individual salaries and the reply is made public. The script refuses to
   publish anything that is not exactly `{"bands":[...]}` or that contains any number other than
   the bands, then fetches the model's signature over `model:sha256(request):sha256(response)`.
4. **Publish.** `publish` parses the request on chain and requires exactly: the round's model, no
   streaming, no fields beyond model/messages/stream/temperature/chat_template_kwargs/max_tokens,
   and messages = [system: the pinned instruction ciphertext] + [user: each stored ciphertext,
   once, in on-chain order]. It then checks the ed25519 signature under the round's key
   (`env::ed25519_verify`), that every band covers at least `k_min` people with a count matching
   the chain, and that smaller groups get no band. The throwaway key is stored with it.
5. **Verify.** On the page, *Run the checks* re-does all of that in the browser, re-encrypts the
   instruction from its plain text, decrypts the signed reply with the published key, compares it
   with the bands, and re-fetches the attestation.

### What is and is not guaranteed

| Guarantee | Enforced by |
| --- | --- |
| Nobody outside the enclave sees a salary (organiser, aggregator, gateway, chain) | Browser encryption to the attested model key |
| The enclave received exactly the pinned instruction and each submission once, as separate messages, nothing else | Contract parses the signed request; browser re-checks |
| The instruction says what the page shows | Published ephemeral secret; browser re-encrypts |
| The published bands are what the enclave replied | Signature over the exact reply; reply decryptable with the published key |
| No band for a group under `k_min` | Contract, against on-chain counts |
| **The percentiles are arithmetically correct** | **Not guaranteed.** A language model computes them. The signature proves inputs and output, not the math. See Limits. |

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

Open https://aditya-galaxy.github.io/payband/ . It opens round `acme-demo-11141842`, the one recorded in the demo video
(marked **Demo round**: nine test accounts at a made-up company, made-up salaries, but real
testnet transactions and real NEAR AI Cloud inference): nine encrypted submissions (four Engineer L2, four Engineer L3, one Staff
Engineer), published bands for the two groups of four, and Staff Engineer marked as never
published. Press **Run the checks**: seven lines turn green (both hashes; the request is exactly the pinned
instruction plus each of the 9 submissions once, in order; the instruction re-encrypts from its
plain text; the enclave signature; the decrypted reply equals the bands; the key is attested now).
Type a salary into *Where do you stand?* (it stays in the browser) to see your marker on the band.

Its publish transaction, where the contract parsed the request and checked the enclave signature:
[HXAr4rvf…](https://testnet.nearblocks.io/txns/HXAr4rvf3QpHrkMxXWot9arLNyDnPhWRAiR6cgEGuaHu).
Every submission is listed on the [contract's page](https://testnet.nearblocks.io/address/payband.testnet).

### 2. Run the tests (1 minute)

```sh
cd contract && cargo test          # Rust 1.95+ (near-sdk 5.30)
```

`test result: ok. 19 passed`. The tests sign real ed25519 messages and cover: a valid result is
accepted and the small group suppressed; publishing early; dropping one submission; one
submission duplicated in place of another; a ciphertext smuggled inside another message; an
injected extra record; a swapped instruction; reordered submissions; extra request fields; a
signature by another key; a tampered reply; a band for a group under `k_min`; a wrong count; a
different model; outsiders and late submissions.

### 3. Run your own round (about 8 minutes)

Needs `near-cli-rs`, Node 20+, a NEAR AI Cloud API key in `.env` as `NEARAI_API_KEY=...`, and
testnet accounts. The scripts default to the demo accounts; for a real round with real people,
set `ADMIN` and `EXTRA_MEMBERS` (comma-separated account ids) for `open-round.mjs`, and have each
person submit from the page with *Use a submit-only key* or *Connect wallet*.

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
- **The model does the arithmetic.** A language model can miscompute a percentile, and the
  signature cannot catch that: it binds inputs and output, not correctness. The demo salaries are
  in `scripts/submit-demo.mjs` (Ana's 112,000 is typed on screen), so you can check the showcase
  round yourself:

  | Role | Exact (numpy) p25 / median / p75 | Enclave returned |
  | --- | --- | --- |
  | Engineer L2 | 111k / 118k / 126k | 111k / 118k / 126k |
  | Engineer L3 | 151k / 156k / 161k | **149k** / 156k / 161k |

  Five of six figures are exact; one quartile is $2k low.

  **The deterministic fix is written but not live.** `enclave/` is a Rust program for OutLayer's
  Intel TDX workers that does the same job with plain code instead of a model. It derives a
  per-round X25519 key inside the TEE (an HMAC under a key OutLayer issues only to this exact wasm
  when called by this contract), publishes only the public half, opens each record (bound to its
  round), and computes numpy-style percentiles. Its unit tests pass, including the quartile above
  (151k, where the model said 149k). On 14 Nov, three `request_execution` calls to
  `outlayer.testnet`, with this wasm and with a trivial echo wasm, all timed out without a worker
  response, so it is not wired into the contract. It was not our code: a trivial echo wasm
  (WASI preview 1 and 2, hosted on GitHub and on FastFS) timed out the same way, and so did other
  teams' testnet requests sent minutes apart (e.g. tx `2eVrpYEDqjLAtYoYe3QCwWXarnHy1xEwLyqb4R2FBVxp`,
  `7xCsPaXa3m7e1gZ9JDjWD1S6XHfVz9sJNVSQa9VTLQx`), all ending in `Execution promise failed`.
  The wasm is already on FastFS at
  `test.fastfs.io/acme-cam.testnet/outlayer.testnet/84859e6e…d64d6b.wasm`. Next: once OutLayer's testnet
  workers serve runs again (or on mainnet), have the contract call it at round open (key) and
  close (bands).
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
- **Prompt injection.** A member could put instructions inside their encrypted record. The pinned
  instruction says to treat records as data, and the publish step refuses any reply that is not
  exactly bands, but a malicious record could still skew the result. Whoever runs the aggregation
  cannot inject anything: the contract fixes the request's shape.
- Testnet only. Not audited. "Acme" and its salaries are made up.

## Layout

```
contract/src/lib.rs     rounds, encrypted submissions, publish with on-chain signature + coverage + k checks
contract/src/tests.rs   19 tests with real ed25519 signatures
enclave/                deterministic aggregator for OutLayer's TEE (unit-tested; not deployed, see Limits)
WALKTHROUGH.md          a 2-minute live demo script
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
