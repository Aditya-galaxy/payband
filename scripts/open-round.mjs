// Opens a round on the contract, pinning the model key from a fresh attestation report.
//   node scripts/open-round.mjs <round_id> <minutes-open>
import { attestedKeys } from './e2ee.mjs';
import { call, view, EXPLORER } from './near.mjs';
const [roundId, minutes = '6'] = process.argv.slice(2);
if (!roundId) { console.error('usage: node scripts/open-round.mjs <round_id> [minutes-open]'); process.exit(2); }
const ADMIN = process.env.ADMIN || 'acme-cam.testnet';
const MODEL = process.env.MODEL || 'deepseek-ai/DeepSeek-V4.1-Flash-1017';
const people = ['ana', 'ben', 'chen', 'dara', 'eli', 'fay', 'gus', 'hana', 'ivo'].map(n => `${n}.acme-cam.testnet`);
const { candidates } = await attestedKeys(MODEL);
if (!candidates.length) throw new Error('no attested ed25519 key for ' + MODEL);
const key = candidates[0].signing_public_key;
console.log(`model ${MODEL}: ${candidates.length} attested instance(s); pinning key ${key}`);
const closes = Math.floor(Date.now() / 1000) + Number(minutes) * 60;
const tx = call(ADMIN, 'create_round', { round_id: roundId, title: 'Acme · engineering pay 2026', currency: 'USD',
  roles: ['Engineer L2', 'Engineer L3', 'Staff Engineer'], members: [...people, ...(process.env.EXTRA_MEMBERS || '').split(',').filter(Boolean)],
  k_min: 4, model: MODEL, model_key: key, closes_at: closes });
console.log(`round ${roundId} open until ${new Date(closes * 1000).toISOString()}  ${EXPLORER}/txns/${tx}`);
console.log(JSON.stringify(await view('get_round', { round_id: roundId })).slice(0, 300));
