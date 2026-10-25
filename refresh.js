// FaceCard HQ refresher. GitHub Actions runs this every 10 minutes.
// It pulls Supabase + RevenueCat and the athletes' objections, encrypts everything
// with HQ_PASSWORD and saves it to Supabase (table hq_public). facecard.tech/hq decrypts it in the browser.
// The dashboard code, config and history live in bundle.enc, encrypted with the same password.
// Secrets: HQ_PASSWORD, SUPABASE_URL, SUPABASE_SERVICE_KEY, REVENUECAT_API_KEY, ANTHROPIC_API_KEY
const fs = require('fs'), zlib = require('zlib'), { webcrypto: crypto } = require('crypto');
const env = process.env;
for (const k of Object.keys(env)) if (typeof env[k] === 'string') env[k] = env[k].trim();
const RC_PROJECT = env.REVENUECAT_PROJECT_ID || 'beb5b746';
const ITER = 150000;

// ---------- crypto (same format the page decrypts) ----------
const b64 = (u) => Buffer.from(u).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
async function keyFor(pw, salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(obj, pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await keyFor(pw, salt), zlib.gzipSync(JSON.stringify(obj), { level: 9 }));
  return JSON.stringify({ v: 1, s: b64(salt), i: b64(iv), c: b64(new Uint8Array(ct)) });
}
async function open(text, pw) {
  const o = JSON.parse(text);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(o.i) }, await keyFor(pw, unb64(o.s)), unb64(o.c));
  return JSON.parse(zlib.gunzipSync(Buffer.from(pt)).toString('utf8'));
}

// ---------- Supabase ----------
const sbBase = () => env.SUPABASE_URL.replace(/\/$/, '') + '/rest/v1/';
const sbHeaders = (extra) => Object.assign({ apikey: env.SUPABASE_SERVICE_KEY }, env.SUPABASE_SERVICE_KEY.startsWith('eyJ') ? { Authorization: 'Bearer ' + env.SUPABASE_SERVICE_KEY } : {}, extra || {});
async function sbGet(path) {
  const step = 1000; let out = [], from = 0;
  while (true) {
    const res = await fetch(sbBase() + path, { headers: sbHeaders({ Range: from + '-' + (from + step - 1), 'Range-Unit': 'items' }) });
    if (!res.ok) throw new Error(path.split('?')[0] + ' returned ' + res.status + ': ' + (await res.text()).slice(0, 200));
    const page = await res.json(); out = out.concat(page);
    if (page.length < step) break; from += step;
  }
  return out;
}
async function sbUpsert(table, row, conflict) {
  const res = await fetch(sbBase() + table + '?on_conflict=' + conflict, { method: 'POST', headers: sbHeaders({ 'content-type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' }), body: JSON.stringify(row) });
  if (!res.ok) throw new Error(table + ' write ' + res.status + ': ' + (await res.text()).slice(0, 200));
}
async function fetchSupabaseRows() {
  const [users, subs, events, excl] = await Promise.all([
    sbGet('user_data?select=id,name,rep_code,created_at,auth_provider,subscription_product_id'),
    sbGet('subscriptions?select=*'),
    sbGet('subscription_events?select=user_id,type,price,period_type,environment,created_at&order=created_at.asc'),
    sbGet('report_excluded_accounts?select=user_id,note').catch(() => [])
  ]);
  const group = (list) => { const m = {}; list.forEach((r) => { (m[r.user_id] = m[r.user_id] || []).push(r); }); return m; };
  const S = group(subs), E = group(events), X = group(excl);
  return users.map((u) => ({ user_id: u.id, signed_up_at: u.created_at, sign_up_method: u.auth_provider || '',
    app_data: JSON.stringify({ user_data: [u], subscriptions: S[u.id] || [], subscription_events: E[u.id] || [], report_excluded_accounts: X[u.id] || [] }) }));
}

// ---------- RevenueCat (API v2) ----------
async function rcGet(path) {
  const url = path.startsWith('http') ? path : 'https://api.revenuecat.com' + (path.startsWith('/v2') ? '' : '/v2') + path;
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url, { headers: { Authorization: 'Bearer ' + env.REVENUECAT_API_KEY } });
    if (res.status === 429 && attempt < 4) { await new Promise((r) => setTimeout(r, 1500 * (attempt + 1))); continue; }
    if (!res.ok) throw new Error(res.status + ': ' + (await res.text()).slice(0, 200));
    return res.json();
  }
}
const toMs = (v) => (v == null || v === '' ? null : typeof v === 'number' ? v : Date.parse(v));
async function fetchRevenueCat(FC) {
  const products = {};
  try { ((await rcGet('/projects/' + RC_PROJECT + '/products?limit=1000')).items || []).forEach((p) => { products[p.id] = p.store_identifier || p.id; }); } catch (e) {}
  let customers = [], next = '/projects/' + RC_PROJECT + '/customers?limit=1000';
  while (next && customers.length < 50000) { const page = await rcGet(next); customers = customers.concat(page.items || []); next = page.next_page || null; }
  const sinceMs = Date.parse(FC.CONFIG.since + 'T00:00:00Z');
  const out = {}, recent = [];
  customers.forEach((c) => {
    const fs = toMs(c.first_seen_at), ls = toMs(c.last_seen_at);
    out[c.id] = { id: c.id, anon: c.id.indexOf('$RCAnonymousID') === 0, firstSeen: fs && fs > Date.UTC(2020, 0, 1) ? new Date(fs) : null,
      trialStart: null, trialEnd: null, trialOptOut: null, firstPurchase: null, spent: 0, plan: null, status: null,
      ghost: ('last_seen_app_version' in c) && !c.last_seen_app_version && !c.last_seen_platform };
    if ((fs && fs >= sinceMs) || (ls && ls >= sinceMs)) recent.push(c.id);
  });
  for (let i = 0; i < recent.length; i += 5) {
    const batch = recent.slice(i, i + 5);
    const pages = await Promise.all(batch.map((id) => rcGet('/projects/' + RC_PROJECT + '/customers/' + encodeURIComponent(id) + '/subscriptions?limit=100').catch(() => null)));
    pages.forEach((page, j) => {
      if (!page) return;
      const c = out[batch[j]];
      (page.items || []).forEach((s) => {
        if (String(s.environment || '').toLowerCase() === 'sandbox') return;
        const gross = (s.total_revenue_in_usd && s.total_revenue_in_usd.gross) || 0;
        const starts = toMs(s.starts_at), ends = toMs(s.current_period_ends_at);
        c.spent += gross; c.ghost = false;
        c.plan = products[s.product_id] || s.product_id || c.plan;
        if (starts && (!c.firstPurchase || starts < c.firstPurchase.getTime())) c.firstPurchase = new Date(starts);
        if (s.status === 'trialing') {
          c.trialStart = starts ? new Date(starts) : c.trialStart;
          c.trialEnd = ends ? new Date(ends) : c.trialEnd;
          c.status = s.auto_renewal_status === 'will_not_renew' ? 'cancelled_trial' : 'free_trial';
          if (c.status === 'cancelled_trial') c.trialOptOut = new Date();
        } else if (s.status === 'active' || s.status === 'in_grace_period' || s.status === 'in_billing_retry') c.status = 'active';
        else if (!c.status) c.status = 'expired';
      });
      c.spent = Math.round(c.spent * 100) / 100;
    });
  }
  return out;
}
function mergeHistory(rc, history) {
  const d = (v) => (v ? new Date(v) : null);
  history.forEach((h) => {
    const c = rc[h[0]] || (rc[h[0]] = { id: h[0], anon: h[0].indexOf('$RCAnonymousID') === 0, firstSeen: null, spent: 0, ghost: false });
    if (h[1]) c.trialStart = d(h[1]); if (h[2]) c.trialEnd = d(h[2]); if (h[3]) c.trialOptOut = d(h[3]); if (h[4]) c.firstPurchase = d(h[4]);
    c.ghost = false; c.spent = Math.max(c.spent || 0, h[5] || 0); c.plan = c.plan || h[6] || null; c.status = c.status || h[7] || null;
  });
  return rc;
}

// ---------- objections + Claude summary ----------
async function insightFor(wk) {
  if (!wk.length) return null;
  const sig = wk.length + ':' + wk[wk.length - 1].at;
  let prev = null;
  try { const r = await sbGet('hq_store?select=value&key=eq.insight'); prev = r[0] && r[0].value; } catch (e) {}
  if (prev && prev.sig === sig) return prev.text;
  if (!env.ANTHROPIC_API_KEY) return prev ? prev.text : null;
  const prompt = 'FaceCard is an iPhone skincare app that athletes sell in person to college students: a face scan, then a 14-day free trial, then $69.99 a year. ' +
    'Below are objections the athletes could not handle this week, each with its category. Write one or two plain sentences for the team: the main pattern, ' +
    'and the one thing training should teach them to say. No names, no quotes, no lists, no preamble.\n\n' + wk.map((o) => '- [' + o.cat + '] ' + o.text).join('\n');
  const res = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: env.ANTHROPIC_MODEL || 'claude-haiku-4-5', max_tokens: 200, messages: [{ role: 'user', content: prompt }] }) });
  if (!res.ok) { console.log('Claude returned ' + res.status + ': ' + (await res.text()).slice(0, 200)); return prev ? prev.text : null; }
  const text = ((await res.json()).content || []).map((b) => b.text || '').join('').trim();
  if (!text) return prev ? prev.text : null;
  await sbUpsert('hq_store', { key: 'insight', value: { sig, text, at: new Date().toISOString() }, updated_at: new Date().toISOString() }, 'key');
  return text;
}

// Page tweaks applied on top of the encrypted page (so small changes don't need a new bundle.enc).
function patchUI(html) {
  const swaps = [
    ["'<p class=\"insight\">' + esc(insight || fallbackInsight(wk, cats, counts)) + '</p>' +",
     "wk.slice().reverse().slice(0, 6).map(function (o) { return '<div class=\"quote\" style=\"font-size:15px;color:var(--ink)\">' + esc(o.text) + '<small>' + esc(o.name || 'Someone') + ' \u00b7 ' + esc(o.cat) + ' \u00b7 ' + new Date(o.at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + '</small></div>'; }).join('') +"]
  ];
  swaps.forEach(([a, b]) => { if (html.includes(a)) html = html.replace(a, b); });
  return html;
}

// ---------- main ----------
(async () => {
  for (const k of ['HQ_PASSWORD', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) if (!env[k]) throw new Error('Missing secret ' + k);
  const bundle = await open(fs.readFileSync(__dirname + '/bundle.enc', 'utf8'), env.HQ_PASSWORD);
  const mod = { exports: {} };
  new Function('module', 'exports', bundle.core)(mod, mod.exports);
  const FC = mod.exports;

  const warn = [];
  let sb = { users: {}, excluded: {}, rows: 0 };
  try { sb = FC.sanitize(FC.fromSupabase(await fetchSupabaseRows())); } catch (e) { warn.push('Supabase: ' + e.message); }
  let rc = {};
  if (env.REVENUECAT_API_KEY) { try { rc = await fetchRevenueCat(FC); } catch (e) { warn.push('RevenueCat: ' + e.message); } }
  else warn.push('RevenueCat key is not set yet.');
  rc = mergeHistory(rc, bundle.history);

  const all = await sbGet('hq_objections?select=created_at,name,cat,text&order=created_at.asc');
  const cut30 = Date.now() - 30 * 864e5, cut7 = Date.now() - 7 * 864e5;
  const objections = all.map((o) => ({ at: o.created_at, name: o.name || '', cat: o.cat || 'Other', text: o.text })).filter((o) => Date.parse(o.at) >= cut30);
  let insight = null;
  try { insight = await insightFor(objections.filter((o) => Date.parse(o.at) >= cut7)); } catch (e) { console.log('Summary: ' + e.message); }

  const label = 'Updated ' + new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(new Date()) + ' ET';
  const data = { sb, rc, meta: { label, warn: warn.join(' '), at: new Date().toISOString() }, objections, insight, cfg: FC.CONFIG };
  const blob = await seal({ html: patchUI(bundle.ui), data }, env.HQ_PASSWORD);
  await sbUpsert('hq_public', { id: 1, blob, updated_at: new Date().toISOString() }, 'id');
  const n = Object.keys(sb.users || {}).length;
  console.log(label + ' | supabase users ' + n + ' | revenuecat customers ' + Object.keys(rc).length + ' | objections ' + objections.length + (warn.length ? ' | WARN ' + warn.join(' ') : ''));
  if (warn.length && !n) process.exit(1);
})().catch((e) => { console.error(e.message); process.exit(1); });
