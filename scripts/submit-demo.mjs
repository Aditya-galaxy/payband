// Demo employees encrypt {role, salary} to the round's model key and submit.
//   node scripts/submit-demo.mjs <round_id>
// The salaries below exist only in this script and in the ciphertexts; nothing else sees them.
import { encryptFor } from './e2ee.mjs';
import { call, view, EXPLORER } from './near.mjs';
const roundId = process.argv[2];
const round = await view('get_round', { round_id: roundId });
const staff = [
  ['ana', 'Engineer L2', 118000], ['ben', 'Engineer L2', 124000], ['chen', 'Engineer L2', 131000], ['dara', 'Engineer L2', 109000],
  ['eli', 'Engineer L3', 152000], ['fay', 'Engineer L3', 147000], ['gus', 'Engineer L3', 168000], ['hana', 'Engineer L3', 159000],
  ['ivo', 'Staff Engineer', 205000],
];
const skip = (process.env.SKIP || '').split(',');
for (const [name, role, salary] of staff.slice(0, Number(process.env.ONLY || staff.length)).filter(([n]) => !skip.includes(n))) {
  const member = `${name}.acme-cam.testnet`;
  const ciphertext = encryptFor(round.model_key, JSON.stringify({ role, salary_usd: salary }));
  const tx = call(member, 'submit', { round_id: roundId, role, ciphertext });
  console.log(`✓ ${member.padEnd(22)} ${role.padEnd(15)} ${ciphertext.slice(0, 24)}…  ${EXPLORER}/txns/${tx}`);
}
