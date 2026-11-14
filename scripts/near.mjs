// Tiny wrappers around near-cli-rs (keys come from ~/.near-credentials, legacy keychain).
import { spawnSync } from 'node:child_process';
export const CONTRACT = process.env.CONTRACT || 'payband.testnet';
export const RPC = process.env.RPC || 'https://test.rpc.fastnear.com';
export const EXPLORER = 'https://testnet.nearblocks.io';

export async function view(method, args = {}) {
  for (let i = 0; i < 6; i++) {
    try {
      const r = await fetch(RPC, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query',
        params: { request_type: 'call_function', finality: 'optimistic', account_id: CONTRACT, method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') } }) });
      const j = await r.json();
      if (j.result?.result) return JSON.parse(Buffer.from(j.result.result).toString());
      if (j.result?.error) throw new Error(j.result.error);
    } catch (e) { if (i === 5) throw e; }
    await new Promise(r => setTimeout(r, 800 * (i + 1)));
  }
}

/** Call a method as `signer`; returns the transaction hash, throws with the contract's panic message. */
export function call(signer, method, args, deposit = '0 NEAR', gas = '100 Tgas') {
  const p = spawnSync('near', ['contract', 'call-function', 'as-transaction', CONTRACT, method, 'json-args', JSON.stringify(args),
    'prepaid-gas', gas, 'attached-deposit', deposit, 'sign-as', signer, 'network-config', 'testnet', 'sign-with-legacy-keychain', 'send'],
    { encoding: 'utf8', maxBuffer: 64 << 20 });
  const out = (String(p.stdout || '') + String(p.stderr || '')).replace(/\x1b\[[0-9;]*m/g, '');
  if (p.status !== 0) throw new Error((out.match(/Smart contract panicked: [^"\n]*/) || [out.slice(-400)])[0]);
  return (out.match(/Transaction ID: (\w+)/) || [])[1] || '';
}
