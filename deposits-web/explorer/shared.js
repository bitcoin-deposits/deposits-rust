// Helpers shared across the explorer pages (explorer.html, ledger.html,
// update.html). Served by the lnurl gateway at /explorer-shared.js;
// import as ES module from each page via:
//
//   import { ... } from './shared.js';
//
// Keeping these in one file lets the per-cosigner ledger lookup, TLV
// decoder, etc. evolve in one place.

// ── URL params (fragment > query) ────────────────────────────────────
//
// Fragment is preferred — it doesn't end up in HTTP referer headers or
// server logs, so dev URLs that pin a remote relay/ledger are safer to
// share.
export function getParam(name) {
  const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  if (hashParams.has(name)) return hashParams.get(name);
  return new URLSearchParams(window.location.search).get(name);
}

// ── breadcrumb nav ───────────────────────────────────────────────────
//
// Context-aware trail built from the URL params (relay/ledger/deposit),
// replacing the old flat tabs (overview | ledger | deposit) that linked to
// id-less detail pages — clicking "deposit" with no id landed you on a blank
// view. Here only a level we actually have an id for becomes a link; the
// current page is the inert tail. Pages may pass `{ ledger, deposit }`
// overrides once they've resolved ids that aren't in the URL.
//
// Renders into `#crumbs` and injects its own CSS once (so the four pages don't
// each duplicate it). Call as e.g. `installBreadcrumbs('deposit', { ledger })`.
let _crumbCssInstalled = false;
export function installBreadcrumbs(current, opts = {}) {
  const el = document.getElementById('crumbs');
  if (!el) return;
  if (!_crumbCssInstalled) {
    const css = document.createElement('style');
    css.textContent = `
      #crumbs { display:flex; flex-wrap:wrap; align-items:center; gap:0.4rem;
                font-size:0.9rem; min-width:0; }
      #crumbs a { color: var(--fg-muted); text-decoration:none; }
      #crumbs a:hover { color: var(--accent); }
      #crumbs .crumb-cur { color: var(--fg-strong); }
      #crumbs .crumb-sep { color: var(--fg-muted); opacity:0.5; }`;
    document.head.appendChild(css);
    _crumbCssInstalled = true;
  }
  const relay = opts.relay || getParam('relay') || '';
  const ledger = opts.ledger || getParam('ledger') || '';
  const deposit = opts.deposit || getParam('deposit') || '';
  const esc = (s) => String(s).replace(/[&<>"]/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const short = (s, n = 16) => (s ? (s.length > n ? s.slice(0, n) + '…' : s) : '');
  const frag = (o) => Object.entries(o).filter(([, v]) => v)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');

  // On a `<id>.ledger.<base>` subdomain the overview crumb must hop off the
  // ledger host to `explorer.<base>`; same-ledger crumbs stay on this host.
  const relayFrag = relay ? '#' + frag({ relay }) : '';
  const sub = window.location.hostname.match(/^[^.]+\.ledger\.(.+)$/);
  const overviewHref = sub
    ? `${window.location.protocol}//explorer.${sub[1]}/${relayFrag}`
    : `/explorer${relayFrag}`;
  const crumbs = [{ label: 'overview', href: overviewHref }];
  if (current === 'ledger' || (ledger && (current === 'deposit' || current === 'update'))) {
    crumbs.push({
      label: `ledger ${short(ledger)}`,
      href: ledger ? `/ledger#${frag({ ledger, relay })}` : null,
    });
  }
  if (current === 'deposit') {
    crumbs.push({ label: `deposit ${short(deposit)}`, href: null });
  } else if (current === 'update') {
    crumbs.push({ label: 'update', href: null });
  }
  el.innerHTML = crumbs.map((c, i) => {
    const last = i === crumbs.length - 1;
    const sep = i > 0 ? '<span class="crumb-sep">›</span>' : '';
    const inner = (c.href && !last)
      ? `<a href="${c.href}">${esc(c.label)}</a>`
      : `<span class="crumb-cur">${esc(c.label)}</span>`;
    return sep + inner;
  }).join('');
}

// ── byte / hex / base64 ──────────────────────────────────────────────
export function bytesToHex(buf) {
  return [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function b64ToBytes(s) {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

// ── tiny Nostr REQ helper ────────────────────────────────────────────
//
// Opens a websocket, sends one filter, accumulates EVENTs, resolves on
// EOSE or timeout. No authentication, no NIP-42; the explorer only
// reads public events.
export function nostrFetch(relayUrl, filter, { timeoutMs = 8000 } = {}) {
  return new Promise((resolve) => {
    const events = [];
    let ws;
    try { ws = new WebSocket(relayUrl); }
    catch { resolve([]); return; }
    const subId = 'q' + Math.random().toString(36).slice(2, 8);
    const finish = () => { try { ws.close(); } catch {} clearTimeout(timer); resolve(events); };
    const timer = setTimeout(finish, timeoutMs);
    ws.onopen = () => ws.send(JSON.stringify(['REQ', subId, filter]));
    ws.onmessage = (msg) => {
      try {
        const d = JSON.parse(msg.data);
        if (d[0] === 'EVENT' && d[1] === subId) events.push(d[2]);
        else if (d[0] === 'EOSE' && d[1] === subId) finish();
      } catch {}
    };
    ws.onerror = finish;
    ws.onclose = finish;
  });
}

// ── BIP-152 / Bitcoin VarInt (Compact Size) ──────────────────────────
function readVarint(buf, off) {
  const b = buf[off];
  if (b < 0xfd) return [b, off + 1];
  if (b === 0xfd) return [(buf[off+1] << 8) | buf[off+2], off + 3];
  if (b === 0xfe) return [(buf[off+1] << 24) | (buf[off+2] << 16) | (buf[off+3] << 8) | buf[off+4], off + 5];
  let val = 0; for (let i = 0; i < 8; i++) val = val * 256 + buf[off + 1 + i];
  return [val, off + 9];
}

// ── TLV parser (matches deposits-protocol's wire encoding) ───────────
export function parseTlv(buf) {
  const records = [];
  let off = 0;
  while (off < buf.length) {
    const startOff = off;
    const [type_, o1] = readVarint(buf, off);
    const [len, o2] = readVarint(buf, o1);
    const value = buf.slice(o2, o2 + len);
    records.push({ type: type_, value, off: startOff, headerLen: o2 - startOff });
    off = o2 + len;
  }
  return records;
}

// ── SignedLedgerUpdate content_hash recompute ────────────────────────
//
// Mirrors the operator's hash chain:
//   sha256(seq_le(8) || prev_hash(32) || message [|| cosig_triples])
//
// Each cosig "triple" is `member_ledger_hash || cosig_signature`. Used
// by /update for the integrity check, and below to find which event
// on a cosigner's ledger has a given content_hash.
export async function computeContentHash(records) {
  const get = (t) => records.find(r => r.type === t)?.value;

  const seqRaw = get(4);
  if (!seqRaw) return null;
  const seqBytes = new Uint8Array(8);
  for (let i = 0; i < Math.min(8, seqRaw.length); i++) seqBytes[i] = seqRaw[i];

  const prevHash = get(6) || new Uint8Array(32);
  const msg = get(8) || new Uint8Array(0);

  const parts = [seqBytes, prevHash, msg];

  const cosigsRaw = get(22);
  if (cosigsRaw && cosigsRaw.length >= 131) {
    let cOff = 0;
    while (cOff + 2 <= cosigsRaw.length) {
      const entryLen = (cosigsRaw[cOff] << 8) | cosigsRaw[cOff + 1];
      cOff += 2;
      if (cOff + entryLen > cosigsRaw.length || entryLen < 129) break;
      const sig = cosigsRaw.slice(cOff + 33, cOff + 97);
      const mh = cosigsRaw.slice(cOff + 97, cOff + 129);
      parts.push(mh); parts.push(sig);
      cOff += entryLen;
    }
  } else {
    const memberHash = get(16);
    const cosignSig = get(18) || new Uint8Array(64);
    if (memberHash) parts.push(memberHash);
    if (cosignSig.some(b => b !== 0)) parts.push(cosignSig);
  }

  const total = parts.reduce((s, p) => s + p.length, 0);
  const all = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { all.set(p, o); o += p.length; }
  const h = await crypto.subtle.digest('SHA-256', all);
  return new Uint8Array(h);
}

// ── QuorumBegin / QuorumAddMember decoders ───────────────────────────

// Decode a QuorumBegin op's (tag 6) member pubkeys + parallel ledger_id
// list (tag 276). Empty map if the op is older and doesn't carry the
// ledger_id field.
export function decodeQuorumBeginMembers(opBytes) {
  const out = new Map();
  let inner;
  try { inner = parseTlv(opBytes); } catch { return out; }
  const disc = inner.find(r => r.type === 0);
  if (!disc || disc.value.length !== 1 || disc.value[0] !== 12) return out;

  const membersField = inner.find(r => r.type === 6);
  if (!membersField) return out;
  const pubkeys = [];
  let off = 0;
  while (off + 33 <= membersField.value.length) {
    pubkeys.push(bytesToHex(membersField.value.slice(off, off + 33)));
    off += 33;
  }
  const lidsField = inner.find(r => r.type === 276);
  const ledgerIds = [];
  if (lidsField) {
    let loff = 0;
    while (loff < lidsField.value.length) {
      const len = lidsField.value[loff];
      loff += 1;
      if (loff + len > lidsField.value.length) break;
      const lid = new TextDecoder().decode(lidsField.value.slice(loff, loff + len));
      ledgerIds.push(lid);
      loff += len;
    }
  }
  pubkeys.forEach((pk, i) => out.set(pk, ledgerIds[i] || ''));
  return out;
}

// Decode a QuorumAddMember op: returns [pubkey_hex, ledger_id] or null.
//   tag 0   = discriminant (must be 43)
//   tag 44  = quorum_member (33-byte compressed pubkey)
//   tag 114 = member_ledger_id (string)
export function decodeQuorumAddMember(opBytes) {
  let inner;
  try { inner = parseTlv(opBytes); } catch { return null; }
  const disc = inner.find(r => r.type === 0);
  if (!disc || disc.value.length !== 1 || disc.value[0] !== 43) return null;
  const pkRec = inner.find(r => r.type === 44);
  const lidRec = inner.find(r => r.type === 114);
  if (!pkRec || pkRec.value.length !== 33 || !lidRec) return null;
  let lid;
  try { lid = new TextDecoder('utf-8', { fatal: false }).decode(lidRec.value); }
  catch { return null; }
  return [bytesToHex(pkRec.value), lid];
}

// Build pubkey → member_ledger_id map for the cosigners of a ledger.
//
// Two-tier lookup:
//   1. Most-recent QuorumBegin's QUORUM_MEMBER_LEDGER_IDS.
//   2. Walk QuorumAddMember ops on this ledger.
//
// Older ledgers whose QuorumBegin lacks the new field still get a
// useful answer via (2) — QuorumAddMember has always carried
// member_ledger_id.
export async function fetchCosignerLedgerMap(relayUrl, ledgerPrefix) {
  // Tier 1: QuorumBegin (op-type tag t=12).
  let events = await nostrFetch(relayUrl, {
    kinds: [9100], '#d': [ledgerPrefix], '#t': ['12'], limit: 5,
  });
  events.sort((a, b) => b.created_at - a.created_at);
  for (const ev of events) {
    let raw, outer, msg;
    try {
      raw = b64ToBytes(ev.content);
      outer = parseTlv(raw);
      msg = outer.find(r => r.type === 8)?.value;
    } catch { continue; }
    if (!msg) continue;
    const map = decodeQuorumBeginMembers(msg);
    if (map.size > 0 && [...map.values()].some(v => v)) return map;
  }

  // Tier 2: QuorumAddMember ops (op-type tag t=43).
  const adds = await nostrFetch(relayUrl, {
    kinds: [9100], '#d': [ledgerPrefix], '#t': ['43'], limit: 100,
  });
  adds.sort((a, b) => a.created_at - b.created_at);
  const map = new Map();
  for (const ev of adds) {
    let raw, outer, msg;
    try {
      raw = b64ToBytes(ev.content);
      outer = parseTlv(raw);
      msg = outer.find(r => r.type === 8)?.value;
    } catch { continue; }
    if (!msg) continue;
    const pair = decodeQuorumAddMember(msg);
    if (pair) map.set(pair[0], pair[1]);
  }
  return map;
}

// Given a ledger and a target content_hash (32 bytes), find the Kind
// 9100 event on that ledger whose decoded content_hash matches.
// Returns the event id (hex) or null.
//
// Fetches up to `limit` events on the ledger, recomputes each one's
// content_hash, returns the first match. Used by /update to resolve
// "the cosigner's tip when they signed" → "click to see THAT update".
export async function findEventByContentHash(relayUrl, ledgerPrefix, targetHashHex, { limit = 200 } = {}) {
  const target = targetHashHex.toLowerCase();
  const events = await nostrFetch(relayUrl, {
    kinds: [9100], '#d': [ledgerPrefix], limit,
  });
  for (const ev of events) {
    let raw, outer;
    try {
      raw = b64ToBytes(ev.content);
      outer = parseTlv(raw);
    } catch { continue; }
    const computed = await computeContentHash(outer);
    if (!computed) continue;
    if (bytesToHex(computed) === target) return ev.id;
  }
  return null;
}

// Parse a miniscript/output descriptor into a fragment tree and render it as
// parsed, indented name/value rows — the same decoded-sub-field style used for
// operation fields, instead of one long string.
//   "tr(K,{and_v(v:pk(A),older(144)),multi_a(2,B,C)})"
export function parseDescriptorTree(s) {
  let i = 0;
  const parseList = (close) => {
    const out = [];
    while (i < s.length && s[i] !== close) {
      if (s[i] === ',') { i++; continue; }
      out.push(parseNode());
    }
    if (s[i] === close) i++;
    return out;
  };
  const parseNode = () => {
    const start = i;
    while (i < s.length && !'({,)}'.includes(s[i])) i++;
    const head = s.slice(start, i).trim();
    if (s[i] === '(') { i++; return { name: head, args: parseList(')') }; }
    if (s[i] === '{') { i++; return { name: head || 'tree', args: parseList('}') }; }
    return { leaf: head };
  };
  return parseNode();
}

function descLeafKind(tok) {
  if (/^-?\d+$/.test(tok)) return 'n';
  if (/^(02|03)?[0-9a-fA-F]{64}$/.test(tok) || /^[xt]pub/.test(tok)) return 'key';
  return 'arg';
}

/// Render a descriptor string as nested `.desc-row` rows. `esc` escapes HTML.
export function renderDescriptorRows(desc, esc) {
  let root;
  try { root = parseDescriptorTree(desc); } catch { return `<div class="desc-row">${esc(desc)}</div>`; }
  let html = '';
  const walk = (n, depth) => {
    const pad = `padding-left:${depth * 14}px`;
    if (n.leaf !== undefined) {
      html += `<div class="desc-row" style="${pad}"><span class="desc-k">${descLeafKind(n.leaf)}</span><span class="desc-v">${esc(n.leaf)}</span></div>`;
      return;
    }
    const leaves = (n.args || []).filter((a) => a.leaf !== undefined);
    if ((n.args || []).length > 0 && leaves.length === n.args.length) {
      html += `<div class="desc-row" style="${pad}"><span class="desc-name">${esc(n.name || 'tree')}</span><span class="desc-v">${n.args.map((a) => esc(a.leaf)).join(', ')}</span></div>`;
    } else {
      html += `<div class="desc-row" style="${pad}"><span class="desc-name">${esc(n.name || 'tree')}</span></div>`;
      (n.args || []).forEach((a) => walk(a, depth + 1));
    }
  };
  walk(root, 0);
  return html;
}
