// An independent verifier for a Stozher audit export, written from spec/01 and spec/04 only.
// Nothing here talks to the kernel: it reads stozher-audit-export.ndjson off disk.
const fs = require('fs');
const crypto = require('crypto');

// RFC 8785 JCS, restricted to the value space this export uses (strings, ints, bools, null,
// arrays, objects). spec/01 section 3.2: sort member names by UTF-16 code unit.
function jcs(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error('non-finite'); return JSON.stringify(v); }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  const keys = Object.keys(v).sort((a, b) => {
    const A = [...a], B = [...b];
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      const x = a.charCodeAt(i), y = b.charCodeAt(i);
      if (x !== y) return x - y;
    }
    return a.length - b.length;
  });
  return '{' + keys.map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}
const objectHash = v => crypto.createHash('sha256').update(Buffer.from(jcs(v), 'utf8')).digest('hex');

function pub(keyId) {
  const raw = Buffer.from(keyId.replace(/^ed25519:/, ''), 'hex');
  return crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]),
    format: 'der', type: 'spki',
  });
}
function verifySigned(obj) {
  if (!obj || !obj.sig) return 'no sig';
  const body = { ...obj }; delete body.sig;
  if (obj.sig.alg !== 'ed25519') return 'alg ' + obj.sig.alg;
  if (!/^ed25519:[0-9a-f]{64}$/.test(obj.sig.key)) return 'malformed key-id';
  const ok = crypto.verify(null, Buffer.from(jcs(body), 'utf8'), pub(obj.sig.key),
                           Buffer.from(obj.sig.value, 'hex'));
  return ok ? null : 'SIGNATURE INVALID';
}

const recs = fs.readFileSync(process.argv[2], 'utf8').split('\n').filter(Boolean).map(JSON.parse);
let fail = 0;
const bad = m => { console.log('  FAIL ' + m); fail++; };

console.log(`records: ${recs.length}`);

// 1. id integrity + envelope signature
for (const r of recs) {
  if (objectHash(r.envelope) !== r.id) bad(`id mismatch ${r.id.slice(0, 12)}`);
  const e = verifySigned(r.envelope);
  if (e) bad(`envelope ${r.id.slice(0, 12)}: ${e}`);
}
console.log('1. envelope id == object-hash, and envelope signature verifies: ' + (fail ? 'FAILED' : 'ok'));

// 2. chain linkage per stream
const before = fail;
const streams = {};
for (const r of recs) (streams[r.envelope.stream] ||= []).push(r);
for (const [name, rs] of Object.entries(streams)) {
  rs.sort((a, b) => a.envelope.seq - b.envelope.seq);
  let prev = null;
  for (let i = 0; i < rs.length; i++) {
    const e = rs[i].envelope;
    if (e.seq !== i) bad(`${name}: seq gap at ${e.seq} (expected ${i})`);
    if ((e['prev-hash'] || null) !== prev) bad(`${name} seq ${e.seq}: prev-hash does not match predecessor id`);
    prev = rs[i].id;
  }
  console.log(`   ${name}: ${rs.length} records, head ${prev.slice(0, 12)}`);
}
console.log('2. hash chain contiguous and linked: ' + (fail > before ? 'FAILED' : 'ok'));

// 3. nested signed objects: mandates, gate decisions, action requests
const b3 = fail;
let mandates = 0, decisions = 0, requests = 0;
for (const r of recs) {
  const e = r.envelope;
  if (e.mandate) { const x = verifySigned(e.mandate); if (x) bad(`mandate in ${r.id.slice(0, 12)}: ${x}`); else mandates++; }
  const a = e.authorization;
  if (a) {
    const x = verifySigned(a.decision); if (x) bad(`decision in ${r.id.slice(0, 12)}: ${x}`); else decisions++;
    // spec/06 4.2: the decision binds a request by its object-hash
    if (a.decision['request-hash'] !== objectHash(a.request))
      bad(`approval in ${r.id.slice(0, 12)} does not bind this request`);
    else requests++;
    // and the effect must be the one the request described
    if (a.request['args-hash'] !== e.execution['args-hash']) bad(`args-hash drift in ${r.id.slice(0, 12)}`);
    if (a.request.action !== e.execution.action) bad(`action drift in ${r.id.slice(0, 12)}`);
    if (a.request.subject !== e.identity.subject) bad(`subject drift in ${r.id.slice(0, 12)}`);
    if (a.request.key !== e.identity.key) bad(`key drift in ${r.id.slice(0, 12)}`);
  }
}
console.log(`3. ${mandates} mandate signatures, ${decisions} approver signatures, ${requests} approval->request bindings: ` + (fail > b3 ? 'FAILED' : 'ok'));

// 4. checkpoints: does a checkpoint attest a head this export contains?
const b4 = fail;
for (const r of recs) {
  const c = r.envelope.checkpoint;
  if (!c) continue;
  const s = (streams[c.stream] || []).map(x => x.id);
  const claimed = c['head-hash'];
  console.log(`   checkpoint over ${c.stream} seq ${c['from-seq']}..${c['to-seq']} head ${claimed.slice(0, 12)} — ${s.includes(claimed) ? 'matches a record in this export' : 'NOT PRESENT in this export'}`);
}
console.log('4. checkpoint cross-check: ' + (fail > b4 ? 'FAILED' : 'ok'));

// 5. what an outsider cannot check from this file alone
console.log('\nnot checkable from this export:');
const roots = new Set();
for (const r of recs) if (r.envelope.mandate) roots.add(r.envelope.mandate.grantor.subject + ' ' + r.envelope.mandate.grantor.key);
console.log('   grantor keys asserting to be human roots: ' + [...roots].join(' | '));
console.log('   the enrolled root set itself is not in this file, so "was this key allowed to grant?" is unanswerable here');
const payloads = recs.filter(r => r.envelope.evidence).length;
console.log(`   ${payloads} records commit to an evidence payload-hash; no payload bytes are in this file`);
console.log(`   policy ${[...new Set(recs.map(r => r.envelope['policy-version']).filter(Boolean))].join(',')} is named but the policy document is not in this file`);

console.log('\n' + (fail ? fail + ' FAILURES' : 'ALL CHECKS PASS'));
