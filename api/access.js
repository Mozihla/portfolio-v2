/* Access requests for locked work (strategy decks + NDA design systems).
 *
 * Flow
 *   1. A visitor fills in the request form on a locked deck/case study  → POST /api/access?a=request
 *      Dammy gets an email with a "Review request" link (signed, valid 7 days).
 *   2. The link opens a review page (GET, safe for email link-scanners) with
 *      Approve / Approve all locked work / Decline buttons                → POST /api/access?a=decide
 *   3. Approve creates a grant that expires 24 hours after approval and emails the visitor
 *      a link: https://www.madebydammy.xyz/?access=<grant>#work/<slug>
 *   4. The site trades the grant for content: the decrypted design-system text (a=open) and
 *      each decrypted image (a=file). Every call re-checks the grant, so after 24 hours
 *      nothing more is served. Visitors never see the access code.
 *
 * Environment (set in Vercel → portfolio-v2 → Settings → Environment Variables)
 *   ACCESS_SECRET   long random string used to sign links (required)
 *   ACCESS_CODE     the 4-digit code the locked work is encrypted with (required to serve content)
 *                   STRAT_CODE / DS_CODE override it per kind if they ever differ
 *   RESEND_API_KEY  Resend API key (required to send email)
 *   OWNER_EMAIL     where requests go, comma-separated for several (required)
 *   MAIL_FROM       sender, e.g. "Dammy Olayiwola <access@madebydammy.xyz>" (domain must be verified in Resend)
 *   SITE_URL        defaults to https://www.madebydammy.xyz
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const SITE = (process.env.SITE_URL || "https://www.madebydammy.xyz").replace(/\/$/, "");
const GRANT_MS = 24 * 60 * 60 * 1000;
const REVIEW_MS = 7 * 24 * 60 * 60 * 1000;

/* ---------- signing ---------- */
const b64u = b => Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = s => Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
function secret() {
  const s = process.env.ACCESS_SECRET || "";
  if (s.length < 16) throw Object.assign(new Error("ACCESS_SECRET is not set"), { code: "setup" });
  return s;
}
function sign(payload) {
  const body = b64u(JSON.stringify(payload));
  const mac = b64u(crypto.createHmac("sha256", secret()).update(body).digest());
  return body + "." + mac;
}
function verify(token, typ) {
  if (typeof token !== "string" || token.length > 4000) return null;
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  const want = crypto.createHmac("sha256", secret()).update(body).digest();
  const got = unb64u(mac);
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) return null;
  let p; try { p = JSON.parse(unb64u(body).toString("utf8")); } catch (e) { return null; }
  if (!p || p.typ !== typ || typeof p.exp !== "number" || Date.now() > p.exp) return null;
  return p;
}

/* ---------- locked content ---------- */
const ROOT = process.cwd();
let LOCKS = null;
function locks() {
  if (LOCKS) return LOCKS;
  const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
  const grab = name => {
    const i = html.indexOf(`window.${name} = `); if (i < 0) return null;
    const j = html.indexOf(";\n", i);
    return JSON.parse(html.slice(i + name.length + 10, j));
  };
  const S = grab("STRAT_LOCK"), D = grab("DS_LOCK");
  const docs = grab("STRAT_DOCS") || [];
  LOCKS = { S, D, docs };
  return LOCKS;
}
/* The catalogue of what can be requested: decks (s) and locked design systems (d) */
function catalogue() {
  const { D, docs } = locks();
  const out = {};
  (docs || []).forEach(d => { out[d.slug] = { kind: "s", title: d.title, client: d.client }; });
  ((D && D.items) || []).forEach(d => { out[d.slug] = { kind: "d", title: d.title, client: d.client }; });
  return out;
}
const KEYS = {};
function keyFor(kind) {
  if (KEYS[kind]) return KEYS[kind];
  const L = kind === "s" ? locks().S : locks().D;
  const code = (kind === "s" ? process.env.STRAT_CODE : process.env.DS_CODE) || process.env.ACCESS_CODE || "";
  if (!L || !/^\d{4}$/.test(code)) throw Object.assign(new Error("ACCESS_CODE is not set"), { code: "setup" });
  KEYS[kind] = crypto.pbkdf2Sync(code, Buffer.from(L.salt, "base64"), L.iter, 32, "sha256");
  return KEYS[kind];
}
/* WebCrypto AES-GCM output = ciphertext || 16-byte tag */
function gcmOpen(key, iv, data) {
  const tag = data.subarray(data.length - 16), ct = data.subarray(0, data.length - 16);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}
const MAPS = {};
function smap() {   // slug → [/assets/s/<hash>.bin, …]
  if (!MAPS.s) { const S = locks().S; MAPS.s = JSON.parse(gcmOpen(keyFor("s"), Buffer.from(S.iv, "base64"), Buffer.from(S.ct, "base64")).toString("utf8")); }
  return MAPS.s;
}
function dlist() {  // [{slug, …case study…}]
  if (!MAPS.d) { const D = locks().D; MAPS.d = JSON.parse(gcmOpen(keyFor("d"), Buffer.from(D.iv, "base64"), Buffer.from(D.ct, "base64")).toString("utf8")); }
  return MAPS.d;
}
function readAsset(p) {
  const clean = path.posix.normalize("/" + String(p || "")).replace(/^\/+/, "");
  if (!/^(assets|media)\//.test(clean) || clean.includes("..")) return null;
  const full = path.join(ROOT, clean);
  return fs.existsSync(full) ? fs.readFileSync(full) : null;
}
const owners = () => String(process.env.OWNER_EMAIL || "").split(",").map(s => s.trim()).filter(Boolean);
const titles = slugs => slugs.map(s => (catalogue()[s] || { title: s }).title);
const listHtml = slugs => `<ul style="margin:0;padding-left:18px">${titles(slugs).map(t => `<li style="margin:2px 0">${esc(t)}</li>`).join("")}</ul>`;
const allowed = (g, slug) => g.scope === "*" || (Array.isArray(g.scope) && g.scope.includes(slug));

/* ---------- email ---------- */
async function mail({ to, subject, html, text, replyTo }) {
  const key = process.env.RESEND_API_KEY;
  if (!key) throw Object.assign(new Error("RESEND_API_KEY is not set"), { code: "setup" });
  const from = process.env.MAIL_FROM || "Dammy's portfolio <onboarding@resend.dev>";
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from, to: Array.isArray(to) ? to : [to], subject, html, text, reply_to: replyTo || undefined }),
  });
  if (!r.ok) { const t = await r.text(); throw Object.assign(new Error(`email failed: ${r.status} ${t.slice(0, 200)}`), { code: "mail" }); }
  return r.json();
}
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const when = ms => new Date(ms).toUTCString().replace(" GMT", " UTC");
const shell = (inner) => `<!doctype html><html><body style="margin:0;background:#f3f1ec;padding:32px 16px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#1b1b1c">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
<table role="presentation" width="100%" style="max-width:560px;background:#fdfcf9;border:1px solid #dcd8d0;border-radius:16px" cellpadding="0" cellspacing="0"><tr><td style="padding:28px 28px 24px">${inner}
<p style="margin:28px 0 0;font-size:12px;color:#66645e">madebydammy.xyz</p></td></tr></table></td></tr></table></body></html>`;
const btn = (href, label) => `<a href="${esc(href)}" style="display:inline-block;background:#f16001;color:#fff;text-decoration:none;padding:12px 20px;border-radius:999px;font-weight:600;font-size:15px">${esc(label)}</a>`;
const row = (k, v) => `<tr><td style="padding:6px 12px 6px 0;color:#66645e;font-size:13px;white-space:nowrap;vertical-align:top">${esc(k)}</td><td style="padding:6px 0;font-size:15px">${v}</td></tr>`;

/* ---------- small helpers ---------- */
function body(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") {
    try { return JSON.parse(req.body); } catch (e) { return require("querystring").parse(req.body); }   // keeps repeated fields as arrays
  }
  return {};
}
const json = (res, code, obj) => { res.statusCode = code; res.setHeader("content-type", "application/json; charset=utf-8"); res.setHeader("cache-control", "no-store"); res.end(JSON.stringify(obj)); };
const page = (res, code, title, inner) => {
  res.statusCode = code; res.setHeader("content-type", "text/html; charset=utf-8"); res.setHeader("cache-control", "no-store");
  res.setHeader("x-robots-tag", "noindex"); res.setHeader("referrer-policy", "no-referrer");
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>:root{--bg:#f3f1ec;--fg:#1b1b1c;--mute:#66645e;--line:#dcd8d0;--card:#fdfcf9;--acc:#f16001}
@media(prefers-color-scheme:dark){:root{--bg:#0a0a0b;--fg:#e7e7e9;--mute:#8a8a90;--line:#26262a;--card:#131315}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:560px;margin:0 auto;padding:48px max(16px,env(safe-area-inset-left)) 64px}
.k{font:500 12px/1 ui-monospace,Menlo,monospace;text-transform:uppercase;letter-spacing:.06em;color:var(--mute);margin:0 0 12px}
h1{font-size:28px;line-height:1.15;letter-spacing:-.02em;margin:0 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px 22px;margin:0 0 20px}
dl{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;margin:0}dt{color:var(--mute);font-size:13px;padding-top:2px}dd{margin:0;overflow-wrap:anywhere}
.acts{display:flex;flex-wrap:wrap;gap:10px}button,.b{font:inherit;font-weight:600;border-radius:999px;padding:11px 18px;border:1px solid var(--line);background:transparent;color:var(--fg);cursor:pointer;text-decoration:none}
button.p{background:var(--acc);border-color:var(--acc);color:#fff}input{font:inherit;width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--fg)}
p.m{color:var(--mute);font-size:14px}.ck{display:flex;gap:10px;align-items:flex-start;padding:7px 0;cursor:pointer}.ck input{width:auto;margin-top:4px;accent-color:var(--acc)}</style></head><body><main>${inner}</main></body></html>`);
};
const HITS = new Map();   // per-instance soft rate limit for requests
function limited(ip) {
  const now = Date.now(), h = (HITS.get(ip) || []).filter(t => now - t < 60 * 60 * 1000);
  h.push(now); HITS.set(ip, h); return h.length > 5;
}

/* ---------- actions ---------- */
async function request(req, res) {
  if (req.method !== "POST") return json(res, 405, { error: "method" });
  const b = body(req);
  if (b.website) return json(res, 200, { ok: true });                    // honeypot: bots fill every field
  const email = String(b.email || "").trim().toLowerCase().slice(0, 200);
  const cat = catalogue();
  const slugs = [...new Set([].concat(b.slugs || b.slug || []).map(String))].filter(s => cat[s]).slice(0, 40);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return json(res, 400, { error: "invalid", message: "Enter a valid email address." });
  if (!slugs.length) return json(res, 400, { error: "invalid", message: "Pick at least one project." });
  const ip = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "?";
  if (limited(ip)) return json(res, 429, { error: "busy", message: "Too many requests from here. Try again in an hour." });
  const r = sign({ typ: "req", email, slugs, at: Date.now(), exp: Date.now() + REVIEW_MS });
  const link = `${SITE}/api/access?a=review&r=${encodeURIComponent(r)}`;
  if (!owners().length) throw Object.assign(new Error("OWNER_EMAIL is not set"), { code: "setup" });
  const what = slugs.length === 1 ? titles(slugs)[0] : `${slugs.length} projects`;
  await mail({
    to: owners(), replyTo: email,
    subject: `Access request: ${what}, from ${email}`,
    text: `${email} asked to see:\n${titles(slugs).map(t => "- " + t).join("\n")}\n\nReview it: ${link}\n\nApproved access lasts 24 hours. This link works for 7 days.`,
    html: shell(`<p style="margin:0 0 6px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:#66645e">Access request</p>
      <h1 style="margin:0 0 18px;font-size:22px;line-height:1.25">${esc(email)} wants to see ${esc(what)}</h1>
      <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 22px">${row("Email", `<a href="mailto:${esc(email)}" style="color:#1b1b1c">${esc(email)}</a>`)}${row("Requested", listHtml(slugs))}</table>
      ${btn(link, "Review request")}
      <p style="margin:18px 0 0;font-size:13px;color:#66645e">Approved access lasts 24 hours. This review link works for 7 days. Reply to this email to write to them directly.</p>`),
  });
  return json(res, 200, { ok: true });
}

function review(req, res) {
  const r = String((req.query && req.query.r) || "");
  const p = verify(r, "req");
  if (!p) return page(res, 410, "Link expired", `<p class="k">Access request</p><h1>This review link has expired or isn't valid.</h1><p class="m">Review links work for 7 days. Ask the person to send a new request from the site.</p>`);
  const t = titles(p.slugs), what = p.slugs.length === 1 ? t[0] : `${p.slugs.length} projects`;
  return page(res, 200, "Review access request", `<p class="k">Access request · ${esc(new Date(p.at).toUTCString().slice(5, 22))} UTC</p>
    <h1>${esc(p.email)} wants to see ${esc(what)}</h1>
    <form method="post" action="/api/access?a=decide"><input type="hidden" name="r" value="${esc(r)}">
      <div class="card"><p class="k" style="margin-bottom:10px">Approve which?</p>
        ${p.slugs.map((s, i) => `<label class="ck"><input type="checkbox" name="s" value="${esc(s)}" checked> ${esc(t[i])}</label>`).join("")}</div>
      <div class="acts"><button class="p" name="d" value="sel">Approve selected</button><button name="d" value="all">Approve all locked work</button><button name="d" value="no">Decline</button></div></form>
    <p class="m">Approval emails ${esc(p.email)} a link that works for 24 hours from now. Decline sends a short, polite note.</p>`);
}

async function decide(req, res) {
  if (req.method !== "POST") return json(res, 405, { error: "method" });
  const b = body(req);
  const p = verify(String(b.r || ""), "req");
  if (!p) return page(res, 410, "Link expired", `<h1>This request has expired or isn't valid.</h1>`);
  const reqWhat = p.slugs.length === 1 ? titles(p.slugs)[0] : `${p.slugs.length} projects`;
  const reply = owners()[0];
  if (b.d === "no") {
    let sent = true;
    try {
      await mail({ to: p.email, replyTo: reply, subject: `About your request to see ${reqWhat}`,
        text: `Hi,\n\nThanks for your interest in ${reqWhat}. I can't share this right now, but I'm happy to talk through the work on a call. Just reply to this email.\n\nDammy`,
        html: shell(`<p style="margin:0 0 14px;font-size:16px">Hi,</p><p style="margin:0 0 14px;font-size:16px;line-height:1.55">Thanks for your interest in <b>${esc(reqWhat)}</b>. I can't share this right now, but I'm happy to talk through the work on a call. Just reply to this email.</p><p style="margin:0;font-size:16px">Dammy</p>`) });
    } catch (e) { sent = false; }
    return page(res, 200, "Declined", `<p class="k">Declined</p><h1>You declined ${esc(p.email)}'s request.</h1><p class="m">${sent ? `They've been sent a short, polite note.` : `The note couldn't be sent, so nothing went out.`}</p>`);
  }
  const all = b.d === "all";
  const picked = [].concat(b.s || []).map(String).filter(s => p.slugs.includes(s));
  if (!all && !picked.length) return page(res, 400, "Nothing selected", `<h1>Tick at least one project, or choose Approve all.</h1><p class="m"><a class="b" href="/api/access?a=review&r=${encodeURIComponent(String(b.r))}">Back</a></p>`);
  const scope = all ? "*" : picked;
  const exp = Date.now() + GRANT_MS;
  const g = sign({ typ: "grant", email: p.email, name: p.email, scope, exp });
  const first = all ? p.slugs[0] : picked[0];
  const link = `${SITE}/?access=${encodeURIComponent(g)}#work/${first}`;
  const what = all ? "all of Dammy's locked work" : picked.length === 1 ? titles(picked)[0] : `${picked.length} projects`;
  let sent = true;
  try {
    await mail({ to: p.email, replyTo: reply, subject: `Your access to ${all ? "Dammy's locked work" : what}`,
      text: `Hi,\n\nYou now have access to ${what}${all ? "" : ":\n" + titles(picked).map(t => "- " + t).join("\n")}\n\nOpen it here:\n${link}\n\nThe link works for 24 hours, until ${when(exp)}. Please don't share it.\n\nDammy`,
      html: shell(`<p style="margin:0 0 14px;font-size:16px">Hi,</p><p style="margin:0 0 12px;font-size:16px;line-height:1.55">You now have access to <b>${esc(what)}</b>.</p>${all || picked.length === 1 ? "" : `<div style="margin:0 0 20px;font-size:15px">${listHtml(picked)}</div>`}${btn(link, "Open the work")}<p style="margin:22px 0 0;font-size:14px;line-height:1.55;color:#66645e">The link works for 24 hours, until ${esc(when(exp))}. Please don't share it.</p><p style="margin:18px 0 0;font-size:16px">Dammy</p>`) });
  } catch (e) { sent = false; }
  return page(res, 200, "Access approved", `<p class="k">Approved</p><h1>${esc(p.email)} can see ${esc(what)} until ${esc(when(exp))}.</h1>
    ${sent ? `<p class="m">We emailed them the link.</p>` : `<p class="m">The email couldn't be sent${process.env.MAIL_FROM ? "" : " (the sending domain isn't set up yet)"}. Copy the link below and send it yourself.</p>`}
    <div class="card"><p class="k" style="margin-bottom:8px">Their access link · works 24 hours</p><input readonly value="${esc(link)}" onclick="this.select()"></div>`);
}

function status(req, res) {
  const g = verify(String((req.query && req.query.g) || ""), "grant");
  if (!g) return json(res, 200, { ok: false });
  return json(res, 200, { ok: true, exp: g.exp, scope: g.scope, name: g.name });
}

/* Decrypted design-system case studies the grant covers */
function open(req, res) {
  const g = verify(String((req.query && req.query.g) || ""), "grant");
  if (!g) return json(res, 401, { error: "expired" });
  // each lock type is opened on its own, so a problem with one never blocks the other
  let items = [], decks = {};
  try { items = dlist().filter(o => allowed(g, o.slug)); } catch (e) { console.error("access ds", e.message); }
  try { decks = Object.fromEntries(Object.entries(smap()).filter(([s]) => allowed(g, s)).map(([s, v]) => [s, v.length])); } catch (e) { console.error("access decks", e.message); }
  return json(res, 200, { ok: true, exp: g.exp, items, decks });
}

/* One decrypted image: deck slide (k=s, slug, i) or design-system image (k=d, p) */
function file(req, res) {
  const q = req.query || {};
  const g = verify(String(q.g || ""), "grant");
  if (!g) { res.statusCode = 401; return res.end(); }
  let data;
  if (q.k === "s") {
    const slug = String(q.slug || ""), i = parseInt(q.i, 10);
    const p = allowed(g, slug) && smap()[slug] && smap()[slug][i];
    const blob = p && readAsset(p);
    if (!blob) { res.statusCode = 404; return res.end(); }
    data = gcmOpen(keyFor("s"), blob.subarray(0, 12), blob.subarray(12));
  } else if (q.k === "d") {
    const p = String(q.p || "");
    const owner = dlist().find(o => JSON.stringify(o).includes(p));
    const blob = owner && allowed(g, owner.slug) && readAsset(p);
    if (!blob) { res.statusCode = 404; return res.end(); }
    const buf = Buffer.from(blob.toString("utf8").trim(), "base64");
    data = gcmOpen(keyFor("d"), buf.subarray(0, 12), buf.subarray(12));
  } else { res.statusCode = 400; return res.end(); }
  res.statusCode = 200;
  res.setHeader("content-type", "image/webp");
  res.setHeader("cache-control", "private, max-age=3600");
  res.setHeader("x-robots-tag", "noindex");
  res.end(data);
}

module.exports = async (req, res) => {
  const a = String((req.query && req.query.a) || "");
  try {
    if (a === "request") return await request(req, res);
    if (a === "review") return review(req, res);
    if (a === "decide") return await decide(req, res);
    if (a === "status") return status(req, res);
    if (a === "open") return open(req, res);
    if (a === "file") return file(req, res);
    return json(res, 404, { error: "unknown" });
  } catch (e) {
    console.error("access", a, e.code || "", e.message);
    if (a === "review" || a === "decide") return page(res, 500, "Something went wrong", `<h1>Something went wrong.</h1><p class="m">${esc(e.code === "setup" ? e.message : "Try again in a minute.")}</p>`);
    return json(res, e.code === "setup" ? 503 : 500, { error: e.code || "failed", message: e.code === "setup" ? "Requests aren't switched on yet." : "Something went wrong. Try again in a minute." });
  }
};
