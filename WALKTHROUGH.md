# Two-minute live walkthrough

No setup on screen. Have https://aditya-galaxy.github.io/payband/ open.

**0:00 · The problem (15 s).** "Am I underpaid? To find out, someone has to see everyone's salary:
HR, a survey vendor, a spreadsheet. The people most underpaid are the least willing to share.
In the EU this is becoming a legal right to ask (Pay Transparency Directive)."

**0:15 · The round (20 s).** Point at the round card. "Nine people, three roles. Each square is an
encrypted submission on NEAR. Staff Engineer has one person: below the minimum of four, so it will
never get a band. Open *instruction the enclave receives*: this was fixed before anyone submitted."

**0:35 · The privacy flow (25 s).** Scroll to the flow line under the headline. "Your browser
fetches the model's attestation from NEAR AI Cloud, encrypts your salary to the key inside that
enclave, and stores only ciphertext on NEAR. The organiser never sees it. Neither do we."

**1:00 · The result (20 s).** Show the bands. "One sealed request went to the enclave; only these
bands came out." Type a salary into *Where do you stand?*: "this never leaves your browser."

**1:20 · Verification, and why NEAR (30 s).** Press *Run the checks*; read the green lines.
"The NEAR contract itself parsed the signed request and refused anything but the fixed instruction
plus each submission once. It verified the enclave's ed25519 signature on chain. Nobody has to
trust whoever ran the aggregation, and anyone can re-check it here."

**1:50 · Honest limit (10 s).** "The model computes the percentiles, so the math is trusted; the
next step is deterministic code in the enclave. Everything else you just saw is enforced."

Fallback if the network is slow: play `video/out/payband-demo.mp4` (92 s) and skip to 1:20.
