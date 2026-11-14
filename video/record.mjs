// Records the narrated Payband demo against testnet + NEAR AI Cloud (needs NEARAI_API_KEY in .env).
//   video/voice.sh && node video/record.mjs
import { chromium } from 'playwright-core';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { mkdirSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'video/out'); rmSync(OUT, { recursive: true, force: true }); mkdirSync(join(OUT, 'frames'), { recursive: true });
const VOICE = join(ROOT, 'video/voice'); const PORT = 4181;
const ANA = 'ana.acme-cam.testnet', ANA_PK = 'ed25519:7Tjeb685bViLocQpycd5zErE5aqBWZwXchZbTR3KoG72';
const ANA_SK = readFileSync(join(homedir(), '.near-credentials/testnet/ana.payband-submit-key.txt'), 'utf8').trim();
const ROUND = 'acme-demo-' + new Date().toISOString().replace(/\D/g, '').slice(4, 12);
const WINDOW_MIN = Number(process.env.WINDOW_MIN || 2);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = m => console.log(`[${new Date().toISOString().slice(11, 19)}] ${m}`);
const node = (args, extra = {}) => { const p = spawnSync('node', args, { cwd: ROOT, encoding: 'utf8', env: { ...process.env, ...extra } }); if (p.status) throw new Error(p.stdout + p.stderr); return p.stdout; };

log(`opening ${ROUND}`); log(node(['scripts/open-round.mjs', ROUND, String(WINDOW_MIN)]).split('\n')[1]);
const server = spawn('python3', ['-m', 'http.server', String(PORT), '--directory', ROOT], { stdio: 'ignore' });
await sleep(1000);
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const ctx = await browser.newContext({ viewport: { width: 1280, height: 720 } });
await ctx.addInitScript(({ acct, pk, sk }) => {
  localStorage.setItem('payband_wallet_auth_key', JSON.stringify({ accountId: acct, allKeys: [pk] }));
  localStorage.setItem(`near-api-js:keystore:${acct}:testnet`, sk);
}, { acct: ANA, pk: ANA_PK, sk: ANA_SK });
const page = await ctx.newPage();
page.on('pageerror', e => log('PAGE ERROR ' + e.message));

const clipLen = k => Number(execFileSync('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', join(VOICE, `${k}.wav`)], { encoding: 'utf8' }));
const segments = [], spoken = [];
let recording = false, n = 0, last = Date.now(), speed = 1, busyUntil = 0;
const videoNow = () => segments.reduce((t, s) => t + s[1], 0) + (recording ? (Date.now() - last) / 1000 / speed : 0);
const say = async k => { while (videoNow() < busyUntil) await sleep(40); const t = videoNow() + 0.15; spoken.push([k, t]); busyUntil = t + clipLen(k) + 0.3; log(`say ${k} @ ${t.toFixed(1)}s`); };
const spokenOut = async () => { while (videoNow() < busyUntil) await sleep(40); };
const card = async (name, voice) => {
  await page.goto(`http://localhost:${PORT}/video/card.html?card=${name}`); await sleep(400);
  await page.screenshot({ path: join(OUT, 'frames', `${name}.jpg`), type: 'jpeg', quality: 92 });
  const t = videoNow() + 0.5; spoken.push([voice, t]); segments.push([`${name}.jpg`, 0.5 + clipLen(voice) + 0.8]); busyUntil = t + clipLen(voice);
};
await card('intro', 'intro');

await page.goto(`http://localhost:${PORT}/docs/index.html?round=${ROUND}&embed=1`);
await page.waitForSelector('#subform');
await page.addStyleTag({ content: `
  #cap { position: fixed; left: 0; right: 0; bottom: 0; padding: 15px 28px; background: rgba(8,7,12,.95); border-top: 1px solid #272533;
    font: 600 21px/1.3 -apple-system, sans-serif; color: #fff; z-index: 9; text-align: center; }
  #cap small { display: block; font: 400 13.5px -apple-system, sans-serif; color: #9b97ab; margin-top: 3px; }
  .wrap { padding-bottom: 130px !important; } .toast { bottom: 92px !important; }` });
await page.evaluate(() => document.body.insertAdjacentHTML('beforeend', '<div id="cap"></div>'));
const cap = (t, sub = '') => page.evaluate(([t, sub]) => { document.getElementById('cap').innerHTML = t + (sub ? `<small>${sub}</small>` : ''); }, [t, sub]);
const scrollTo = sel => page.evaluate(s => document.querySelector(s)?.scrollIntoView({ block: 'center', behavior: 'smooth' }), sel);

recording = true; last = Date.now();
const loop = (async () => { while (recording) { const f = `f${String(n++).padStart(5, '0')}.jpg`; await page.screenshot({ path: join(OUT, 'frames', f), type: 'jpeg', quality: 88 }); const now = Date.now(); segments.push([f, (now - last) / 1000 / speed]); last = now; await sleep(50); } })();

await cap('Ana, an engineer at Acme, adds her salary.', 'signed in with a key that can only call submit');
await scrollTo('#subform'); await sleep(800);
await say('ana');
await page.selectOption('#srole', 'Engineer L2');
for (const ch of '112000') { await page.type('#ssal', ch); await sleep(140); }
await sleep(600); await page.click('#sbtn');
await page.waitForFunction(() => /stored on NEAR/.test(document.getElementById('ssteps')?.textContent || '') || /submitted/.test(document.body.textContent), null, { timeout: 60000 }).catch(() => log('ana submit not confirmed'));
await sleep(1500); await spokenOut();
await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
await cap('Eight colleagues submit the same way.', 'only ciphertext reaches NEAR · fast-forward 3x');
await say('others'); speed = 3;
node(['scripts/submit-demo.mjs', ROUND], { SKIP: 'ana' });
speed = 1; await sleep(1500); await spokenOut();
await cap('Staff Engineer has one person, under the minimum of four: no band, ever.');
await sleep(2500);
speed = 4; await cap('Waiting for the round to close…', 'fast-forward');
await page.waitForFunction(() => /closed/i.test(document.querySelector('.status')?.textContent || ''), null, { timeout: (WINDOW_MIN * 60 + 60) * 1000 });
speed = 1;
await cap('Closed. All ciphertexts go to the model in its attested enclave, in one sealed request.', 'NEAR AI Cloud · end-to-end encrypted · the reply is signed by the enclave key');
await say('close');
speed = 2; log(node(['scripts/aggregate.mjs', ROUND]).trim().split('\n').slice(-3).join(' | '));
await page.waitForSelector('.band', { timeout: 60000 }); speed = 1;
await spokenOut();
await cap('Only the bands come out, accepted on chain because the enclave’s signature verified.');
await scrollTo('.bands'); await say('bands'); await sleep(2000); await spokenOut();
await cap('Anyone can verify it, in the browser.');
await scrollTo('#verify'); await sleep(900); await say('verify');
await page.click('#vbtn');
await page.waitForSelector('#verify .steps', { timeout: 60000 }); await sleep(3500); await spokenOut();
await cap('Ana compares her own salary. It never leaves her browser.');
await scrollTo('#msal'); await sleep(700);
await page.selectOption('#mrole', 'Engineer L2');
for (const ch of '112000') { await page.type('#msal', ch); await sleep(110); }
await page.click('#mbtn'); await sleep(300); await scrollTo('.bands');
await say('mine'); await sleep(2500); await spokenOut(); await sleep(800);
recording = false; await loop;
await card('outro', 'outro');
await browser.close(); server.kill();

const list = segments.map(([f, d]) => `file 'frames/${f}'\nduration ${Math.max(d, 0.04).toFixed(3)}`).join('\n') + `\nfile 'frames/${segments.at(-1)[0]}'\n`;
writeFileSync(join(OUT, 'list.txt'), list);
const total = segments.reduce((t, s) => t + s[1], 0);
const ins = spoken.flatMap(([k]) => ['-i', join(VOICE, `${k}.wav`)]);
const filt = spoken.map(([, t], i) => `[${i + 1}:a]adelay=${Math.round(t * 1000)}:all=1[a${i}]`).join(';') +
  `;${spoken.map((_, i) => `[a${i}]`).join('')}amix=inputs=${spoken.length}:normalize=0,apad=whole_dur=${total.toFixed(2)},loudnorm=I=-16:TP=-1.5[a]`;
execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', join(OUT, 'list.txt'), ...ins,
  '-filter_complex', `[0:v]fps=30,format=yuv420p[v];${filt}`, '-map', '[v]', '-map', '[a]', '-c:v', 'libx264', '-crf', '21', '-c:a', 'aac', '-b:a', '160k', '-t', total.toFixed(2), '-movflags', '+faststart', join(OUT, 'payband-demo.mp4')]);
log(`done: ${total.toFixed(1)}s → video/out/payband-demo.mp4 · round ${ROUND}`);
