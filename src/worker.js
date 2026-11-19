import { slugify, DEFAULT_REGIONS, DEFAULT_EVENT_NAME } from "./regions.js";

const HOLD_MS = 5 * 60 * 1000; // เวลาโอนเงินหลังกดยืนยัน
const GRACE_MS = 10 * 1000; // เผื่อเวลาให้สลิปที่กำลังอัปโหลดอยู่
const MAX_IMG = 1900000; // D1 เก็บได้ไม่เกิน 2 MB ต่อแถว
const MAX_PER_IP = 3; // จำนวนประเทศที่กำลังรอโอนต่อ 1 IP
const OWNER_RE = /^[A-Za-z0-9_-]{20,64}$/;
const USER_RE = /^@[A-Za-z0-9_.]{2,32}$/;
const ID_RE = /^[a-f0-9]{32}$/;

const enc = new TextEncoder();
let memo = null; // แคชข้อมูลสาธารณะ 2 วินาทีต่อ isolate

/* ---------- helpers ---------- */
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}
const fail = (status, error, message) => json({ error, message }, status);
const now = () => Date.now();
const live = (c, t) => c.slip_at != null || t < c.expires_at + GRACE_MS;
function randId() {
  const a = crypto.getRandomValues(new Uint8Array(16));
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
}
function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function secret(env) {
  return env.SESSION_SECRET || env.ADMIN_PASSWORD || "";
}
function getCookie(req, name) {
  const m = (req.headers.get("cookie") || "").match(new RegExp("(?:^|;\\s*)" + name + "=([^;]*)"));
  return m ? m[1] : "";
}
async function isAdmin(req, env) {
  const s = secret(env);
  if (!s) return false;
  const v = getCookie(req, "mm_admin");
  const [exp, sig] = v.split(".");
  if (!exp || !sig || Number(exp) < now()) return false;
  return safeEq(sig, await hmac(s, "admin." + exp));
}
function ownerOf(req) {
  const t = req.headers.get("x-owner") || "";
  return OWNER_RE.test(t) ? t : "";
}
function sniff(bytes) {
  const b = bytes;
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return "image/webp";
  return "";
}
async function readImage(file) {
  if (!file || typeof file === "string" || typeof file.arrayBuffer !== "function") return { error: "ไม่พบไฟล์รูป" };
  if (file.size > MAX_IMG) return { error: "ไฟล์ใหญ่เกินไป (ไม่เกิน 1.9 MB หลังย่อ)" };
  const buf = await file.arrayBuffer();
  const mime = sniff(new Uint8Array(buf, 0, Math.min(16, buf.byteLength)));
  if (!mime) return { error: "รองรับเฉพาะไฟล์ png, jpg หรือ webp" };
  return { buf, mime };
}
// รูปถูกแบ่งเก็บเป็นก้อนละ ~400 KB เพื่อไม่ชนข้อจำกัดขนาดของ D1
const CHUNK = 400 * 1024;
function insertImageStmts(env, id, kind, mime, buf) {
  const stmts = [env.DB.prepare("INSERT INTO images (id, kind, mime, size, created_at) VALUES (?, ?, ?, ?, ?)").bind(id, kind, mime, buf.byteLength, now())];
  for (let i = 0, n = 0; i < buf.byteLength; i += CHUNK, n++) {
    stmts.push(env.DB.prepare("INSERT INTO image_chunks (image_id, idx, data) VALUES (?, ?, ?)").bind(id, n, buf.slice(i, i + CHUNK)));
  }
  return stmts;
}
function deleteImageStmts(env, id) {
  return [
    env.DB.prepare("DELETE FROM image_chunks WHERE image_id = ?").bind(id || "none"),
    env.DB.prepare("DELETE FROM images WHERE id = ?").bind(id || "none"),
  ];
}
function toBytes(d) {
  if (d instanceof ArrayBuffer) return new Uint8Array(d);
  if (ArrayBuffer.isView(d)) return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
  return Uint8Array.from(d || []); // D1 บางรุ่นคืนค่าเป็นอาร์เรย์ตัวเลข
}
async function kvGet(env, key, fallback) {
  const r = await env.DB.prepare("SELECT value FROM kv WHERE key = ?").bind(key).first();
  if (!r) return fallback;
  try { return JSON.parse(r.value); } catch { return fallback; }
}
function kvSet(env, key, value) {
  return env.DB.prepare("INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(key, JSON.stringify(value));
}
async function getRegions(env) {
  const r = await kvGet(env, "regions", null);
  return Array.isArray(r) && r.length ? r : DEFAULT_REGIONS;
}
function cleanTheme(t) {
  const hex = (v) => (typeof v === "string" && /^#[0-9a-fA-F]{6}$/.test(v) ? v.toLowerCase() : "");
  t = t || {};
  return { bg: hex(t.bg), accent: hex(t.accent), gold: hex(t.gold) };
}
function cleanSettings(s) {
  return { fee: s.fee ?? null, open: s.open !== false, opensAt: s.opensAt ?? null, closesAt: s.closesAt ?? null, note: s.note || "", eventName: s.eventName || DEFAULT_EVENT_NAME, theme: cleanTheme(s.theme) };
}
function schedule(s, t) {
  if (s.open === false) return false;
  if (s.opensAt && t < s.opensAt) return false;
  if (s.closesAt && t >= s.closesAt) return false;
  return true;
}
function stateOf(c, slip, rv) {
  if (c.slip_at == null) return "unpaid";
  if (!slip) return "pending";
  if (rv && rv.at >= slip.uploaded_at) return rv.status === "approved" ? "approved" : "rejected";
  return "pending";
}
function pubClaim(r) {
  return { slug: r.slug, country: r.country, continent: r.continent, username: r.username, fullName: r.full_name, photoId: r.photo_id, claimedAt: r.claimed_at };
}

/* ---------- public state (cached 2s) ---------- */
async function publicState(env) {
  const t = now();
  if (memo && t - memo.at < 2000) return memo.data;
  const [taken, approved, settings, content, regions] = await Promise.all([
    env.DB.prepare("SELECT slug, slip_at IS NOT NULL AS paid FROM countries WHERE slip_at IS NOT NULL OR expires_at + ? > ?").bind(GRACE_MS, t).all(),
    env.DB.prepare(
      "SELECT c.* FROM countries c JOIN slips s ON s.slug = c.slug JOIN reviews r ON r.slug = c.slug WHERE r.status = 'approved' AND r.at >= s.uploaded_at ORDER BY c.claimed_at"
    ).all(),
    kvGet(env, "settings", {}),
    kvGet(env, "content", {}),
    getRegions(env),
  ]);
  const tk = {};
  for (const r of taken.results) tk[r.slug] = { paid: !!r.paid };
  const data = { taken: tk, approved: approved.results.map(pubClaim), settings: cleanSettings(settings), content, regions };
  memo = { at: t, data };
  return data;
}
async function myClaims(env, owner) {
  if (!owner) return [];
  const t = now();
  const rows = await env.DB.prepare(
    "SELECT c.*, s.image_id AS s_img, s.amount AS s_amount, s.uploaded_at AS s_at, r.status AS r_status, r.note AS r_note, r.at AS r_at FROM countries c LEFT JOIN slips s ON s.slug = c.slug LEFT JOIN reviews r ON r.slug = c.slug WHERE c.owner = ? ORDER BY c.claimed_at"
  ).bind(owner).all();
  return rows.results
    .filter((c) => live(c, t))
    .map((c) => {
      const slip = c.s_img ? { image_id: c.s_img, amount: c.s_amount, uploaded_at: c.s_at } : null;
      const rv = c.r_status ? { status: c.r_status, note: c.r_note, at: c.r_at } : null;
      return {
        ...pubClaim(c),
        expiresAt: c.expires_at,
        slipAt: c.slip_at,
        state: stateOf(c, slip, rv),
        note: rv && rv.status === "rejected" && slip && rv.at >= slip.uploaded_at ? rv.note || "" : "",
        slip: slip ? { imageId: slip.image_id, amount: slip.amount, uploadedAt: slip.uploaded_at } : null,
      };
    });
}

/* ---------- public API ---------- */
async function apiState(req, env) {
  const pub = await publicState(env);
  const owner = ownerOf(req);
  const [me, admin] = await Promise.all([myClaims(env, owner), isAdmin(req, env)]);
  return json({ now: now(), ...pub, me, admin });
}

async function apiClaim(req, env, ip) {
  const owner = ownerOf(req);
  if (!owner) return fail(400, "bad_owner", "ไม่พบรหัสเบราว์เซอร์ ลองโหลดหน้าใหม่");
  let form;
  try { form = await req.formData(); } catch { return fail(400, "bad_form", "ข้อมูลไม่ถูกต้อง"); }
  const slug = String(form.get("slug") || "");
  const username = String(form.get("username") || "").trim();
  const fullName = String(form.get("fullName") || "").trim().replace(/\s+/g, " ");
  const regions = await getRegions(env);
  const reg = regions.find((r) => r.slug === slug);
  const c = reg ? { name: reg.name, continent: "area" } : null;
  const t = now();
  const settings = cleanSettings(await kvGet(env, "settings", {}));
  if (!schedule(settings, t)) return fail(403, "closed", "ตอนนี้ยังไม่เปิดหรือปิดรับสมัครแล้ว");
  if (!c) return fail(400, "bad_country", "ไม่พบพื้นที่นี้");
  if (!USER_RE.test(username)) return fail(400, "bad_username", "Username ไม่ถูกต้อง เช่น @mali");
  if (fullName.length < 2 || fullName.length > 60) return fail(400, "bad_name", "ชื่อและนามสกุลไม่ถูกต้อง");

  // 1 คน สมัครได้ 1 พื้นที่ (นับทั้งรหัสเบราว์เซอร์และ Username ไม่สนตัวพิมพ์ใหญ่เล็ก)
  const mine = await myClaims(env, owner);
  if (mine.length >= 1) return fail(409, "limit", "คุณลงสมัครไปแล้ว 1 พื้นที่ (สมัครได้คนละ 1 พื้นที่)");
  const same = (await env.DB.prepare("SELECT slug FROM countries WHERE lower(username) = ? AND (slip_at IS NOT NULL OR expires_at + ? > ?)").bind(username.toLowerCase(), GRACE_MS, t).all()).results || [];
  if (same.length >= 1) return fail(409, "username_limit", "Username นี้ลงสมัครไปแล้ว (สมัครได้คนละ 1 พื้นที่)");

  const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM countries WHERE ip = ? AND slip_at IS NULL AND expires_at + ? > ?").bind(ip, GRACE_MS, t).first();
  if (cnt && cnt.n >= MAX_PER_IP) return fail(429, "too_many", "มีพื้นที่ที่รอโอนเงินจากอุปกรณ์นี้หลายรายการแล้ว รอให้หมดเวลาหรือแนบสลิปก่อน");

  let photoId = null, img = null;
  const file = form.get("photo");
  if (file && typeof file !== "string" && file.size > 0) {
    img = await readImage(file);
    if (img.error) return fail(400, "bad_photo", img.error);
    photoId = randId();
  }
  const stmts = [
    env.DB.prepare("DELETE FROM countries WHERE slug = ? AND slip_at IS NULL AND expires_at + ? <= ?").bind(slug, GRACE_MS, t),
    env.DB.prepare("DELETE FROM reviews WHERE slug = ? AND NOT EXISTS (SELECT 1 FROM countries WHERE slug = ?)").bind(slug, slug),
  ];
  if (img) stmts.push(...insertImageStmts(env, photoId, "profile", img.mime, img.buf));
  stmts.push(
    env.DB.prepare(
      "INSERT INTO countries (slug, owner, country, continent, username, full_name, photo_id, claimed_at, expires_at, slip_at, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)"
    ).bind(slug, owner, c.name, c.continent, username, fullName, photoId, t, t + HOLD_MS, ip)
  );
  try {
    await env.DB.batch(stmts);
  } catch (e) {
    if (/UNIQUE|constraint/i.test(String(e && e.message))) return fail(409, "taken", "มีคนกดยืนยันพื้นที่นี้ก่อนคุณ");
    throw e;
  }
  memo = null;
  return json({ ok: true, slug, expiresAt: t + HOLD_MS });
}

async function ownedLive(env, slug, owner) {
  const c = await env.DB.prepare("SELECT * FROM countries WHERE slug = ? AND owner = ?").bind(slug, owner).first();
  return c && live(c, now()) ? c : null;
}

async function apiPhoto(req, env) {
  const owner = ownerOf(req);
  const form = await req.formData();
  const slug = String(form.get("slug") || "");
  const c = owner && (await ownedLive(env, slug, owner));
  if (!c) return fail(410, "gone", "ประเทศนี้ไม่ได้อยู่กับคุณแล้ว");
  const img = await readImage(form.get("photo"));
  if (img.error) return fail(400, "bad_photo", img.error);
  const id = randId();
  await env.DB.batch([
    ...insertImageStmts(env, id, "profile", img.mime, img.buf),
    env.DB.prepare("UPDATE countries SET photo_id = ? WHERE slug = ? AND owner = ?").bind(id, slug, owner),
    ...deleteImageStmts(env, c.photo_id),
  ]);
  memo = null;
  return json({ ok: true });
}

async function apiSlip(req, env) {
  const owner = ownerOf(req);
  const form = await req.formData();
  const slug = String(form.get("slug") || "");
  const amount = form.get("amount") ? Number(form.get("amount")) : null;
  if (amount != null && !(amount >= 0 && amount < 1e7)) return fail(400, "bad_amount", "จำนวนเงินไม่ถูกต้อง");
  if (!owner) return fail(400, "bad_owner", "ไม่พบรหัสเบราว์เซอร์");
  const img = await readImage(form.get("slip"));
  if (img.error) return fail(400, "bad_slip", img.error);
  const t = now();
  const old = await env.DB.prepare("SELECT image_id FROM slips WHERE slug = ?").bind(slug).first();
  const id = randId();
  const ins = insertImageStmts(env, id, "slip", img.mime, img.buf);
  const res = await env.DB.batch([
    ...ins,
    env.DB.prepare("UPDATE countries SET slip_at = ? WHERE slug = ? AND owner = ? AND (slip_at IS NOT NULL OR expires_at + ? > ?)").bind(t, slug, owner, GRACE_MS, t),
    env.DB.prepare("INSERT OR REPLACE INTO slips (slug, image_id, amount, uploaded_at) SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM countries WHERE slug = ? AND owner = ? AND slip_at = ?)").bind(slug, id, amount, t, slug, owner, t),
  ]);
  if (!res[ins.length].meta.changes) {
    await env.DB.batch(deleteImageStmts(env, id));
    return fail(410, "gone", "หมดเวลาแล้ว ประเทศหลุดไปแล้ว ต้องกรอกและเลือกใหม่");
  }
  if (old) await env.DB.batch(deleteImageStmts(env, old.image_id));
  memo = null;
  return json({ ok: true });
}

async function serveImage(req, env, id) {
  if (!ID_RE.test(id)) return new Response("not found", { status: 404 });
  const r = await env.DB.prepare("SELECT kind, mime, size FROM images WHERE id = ?").bind(id).first();
  if (!r) return new Response("not found", { status: 404 });
  let cache = "public, max-age=31536000, immutable";
  if (r.kind === "slip") {
    let ok = await isAdmin(req, env);
    if (!ok) {
      const owner = ownerOf(req);
      const q = owner && (await env.DB.prepare("SELECT 1 AS x FROM slips s JOIN countries c ON c.slug = s.slug WHERE s.image_id = ? AND c.owner = ?").bind(id, owner).first());
      ok = !!q;
    }
    if (!ok) return new Response("forbidden", { status: 403 });
    cache = "private, no-store";
  }
  const rows = await env.DB.prepare("SELECT data FROM image_chunks WHERE image_id = ? ORDER BY idx").bind(id).all();
  const out = new Uint8Array(r.size);
  let off = 0;
  for (const row of rows.results) {
    const b = toBytes(row.data);
    out.set(b, off);
    off += b.length;
  }
  return new Response(out, { headers: { "content-type": r.mime, "cache-control": cache, "x-content-type-options": "nosniff" } });
}

/* ---------- admin API ---------- */
async function adminLogin(req, env) {
  const s = secret(env);
  if (!s) return fail(500, "no_secret", "ยังไม่ได้ตั้ง ADMIN_PASSWORD ใน Cloudflare");
  let body = {};
  try { body = await req.json(); } catch {}
  const pw = String(body.password || "");
  const ok = env.ADMIN_PASSWORD && safeEq(await hmac(s, "pw." + pw), await hmac(s, "pw." + env.ADMIN_PASSWORD));
  if (!ok) {
    await new Promise((r) => setTimeout(r, 600));
    return fail(401, "bad_password", "รหัสผ่านไม่ถูกต้อง");
  }
  const exp = now() + 12 * 3600 * 1000;
  const sig = await hmac(s, "admin." + exp);
  return json({ ok: true }, 200, { "set-cookie": `mm_admin=${exp}.${sig}; Path=/; Max-Age=${12 * 3600}; HttpOnly; Secure; SameSite=Strict` });
}

async function adminList(env) {
  const t = now();
  const rows = await env.DB.prepare(
    "SELECT c.*, s.image_id AS s_img, s.amount AS s_amount, s.uploaded_at AS s_at, r.status AS r_status, r.note AS r_note, r.at AS r_at FROM countries c LEFT JOIN slips s ON s.slug = c.slug LEFT JOIN reviews r ON r.slug = c.slug ORDER BY c.claimed_at"
  ).all();
  const list = rows.results
    .filter((c) => live(c, t))
    .map((c) => {
      const slip = c.s_img ? { image_id: c.s_img, amount: c.s_amount, uploaded_at: c.s_at } : null;
      const rv = c.r_status ? { status: c.r_status, note: c.r_note, at: c.r_at } : null;
      return {
        ...pubClaim(c),
        expiresAt: c.expires_at,
        slipAt: c.slip_at,
        state: stateOf(c, slip, rv),
        note: rv ? rv.note || "" : "",
        slip: slip ? { imageId: slip.image_id, amount: slip.amount, uploadedAt: slip.uploaded_at } : null,
      };
    });
  return json({ list });
}

async function adminReview(req, env) {
  const b = await req.json();
  const status = b.status === "approved" ? "approved" : b.status === "rejected" ? "rejected" : "";
  if (typeof b.slug !== "string" || !status) return fail(400, "bad_request", "ข้อมูลไม่ถูกต้อง");
  const slip = await env.DB.prepare("SELECT 1 AS x FROM slips WHERE slug = ?").bind(b.slug).first();
  if (!slip) return fail(409, "no_slip", "ยังไม่มีสลิป");
  await env.DB.prepare("INSERT INTO reviews (slug, status, note, at) VALUES (?, ?, ?, ?) ON CONFLICT(slug) DO UPDATE SET status = excluded.status, note = excluded.note, at = excluded.at")
    .bind(b.slug, status, String(b.note || "").slice(0, 200), now()).run();
  memo = null;
  return json({ ok: true });
}

async function adminRelease(req, env) {
  const b = await req.json();
  if (typeof b.slug !== "string") return fail(400, "bad_request", "ข้อมูลไม่ถูกต้อง");
  const c = await env.DB.prepare("SELECT photo_id FROM countries WHERE slug = ?").bind(b.slug).first();
  const s = await env.DB.prepare("SELECT image_id FROM slips WHERE slug = ?").bind(b.slug).first();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM reviews WHERE slug = ?").bind(b.slug),
    env.DB.prepare("DELETE FROM slips WHERE slug = ?").bind(b.slug),
    env.DB.prepare("DELETE FROM countries WHERE slug = ?").bind(b.slug),
    ...deleteImageStmts(env, c && c.photo_id),
    ...deleteImageStmts(env, s && s.image_id),
  ]);
  memo = null;
  return json({ ok: true });
}

async function adminSettings(req, env) {
  const b = await req.json();
  const num = (v) => (v === null || v === "" || v === undefined ? null : Number.isFinite(Number(v)) ? Number(v) : null);
  const s = {
    fee: num(b.fee),
    open: b.open !== false,
    opensAt: num(b.opensAt),
    closesAt: num(b.closesAt),
    note: String(b.note || "").slice(0, 500),
    eventName: String(b.eventName || "").trim().replace(/\s+/g, " ").slice(0, 40) || DEFAULT_EVENT_NAME,
    theme: cleanTheme(b.theme),
  };
  if (s.opensAt && s.closesAt && s.closesAt <= s.opensAt) return fail(400, "bad_range", "เวลาปิดต้องหลังเวลาเปิด");
  await kvSet(env, "settings", s).run();
  memo = null;
  return json({ ok: true });
}

async function adminContent(req, env) {
  const b = await req.json();
  const id = (v) => (typeof v === "string" && ID_RE.test(v) ? v : null);
  const txt = (v) => String(v || "").slice(0, 100);
  // TikTok: รับ @ชื่อ หรือลิงก์ tiktok.com เท่านั้น แล้วแปลงเป็นลิงก์ https ที่ปลอดภัย
  const tiktok = (v) => {
    const s = String(v || "").trim().slice(0, 200);
    if (!s) return "";
    if (/^@?[A-Za-z0-9._]{1,40}$/.test(s)) return "https://www.tiktok.com/@" + s.replace(/^@/, "");
    try {
      const u = new URL(/^https?:\/\//i.test(s) ? s : "https://" + s);
      const h = u.hostname.toLowerCase();
      if (u.protocol === "https:" && (h === "tiktok.com" || h.endsWith(".tiktok.com"))) return u.origin + u.pathname.replace(/\/+$/, "") ;
    } catch {}
    return "";
  };
  const out = {
    hero: (Array.isArray(b.hero) ? b.hero : []).slice(0, 12).map((x) => id(x && x.asset)).filter(Boolean).map((a) => ({ asset: a })),
    hall: (Array.isArray(b.hall) ? b.hall : []).slice(0, 40).filter((x) => x && id(x.asset)).map((x) => ({ asset: x.asset, name: txt(x.name), title: txt(x.title), tiktok: tiktok(x.tiktok) })),
    continents: {},
  };
  for (const k of ["africa", "america", "europe", "asia"]) if (b.continents && id(b.continents[k])) out.continents[k] = b.continents[k];
  if (b.guide && typeof b.guide === "object") {
    const s = (v, n) => String(v || "").slice(0, n);
    out.guide = {
      rows: (Array.isArray(b.guide.rows) ? b.guide.rows : []).slice(0, 15).map((r) => ({ label: s(r && r.label, 60), text: s(r && r.text, 600) })),
      prompts: (Array.isArray(b.guide.prompts) ? b.guide.prompts : []).slice(0, 8).map((p) => ({ title: s(p && p.title, 100), text: s(p && p.text, 5000) })),
    };
  }
  if (Array.isArray(b.payments)) {
    const s = (v, n) => String(v || "").trim().slice(0, n);
    out.payments = b.payments.map((p) => ({ name: s(p && p.name, 60), no: s(p && p.no, 40), holder: s(p && p.holder, 80), note: s(p && p.note, 200), qr: id(p && p.qr) || "", logo: id(p && p.logo) || "", fee: (p && p.fee !== "" && p.fee != null && Number(p.fee) >= 0 && Number(p.fee) < 1e6) ? Number(p.fee) : null })).filter((p) => p.name || p.no || p.qr || p.logo).slice(0, 6);
  }
  await kvSet(env, "content", out).run();
  memo = null;
  return json({ ok: true, content: out });
}

async function adminImage(req, env) {
  const form = await req.formData();
  const img = await readImage(form.get("file"));
  if (img.error) return fail(400, "bad_image", img.error);
  const id = randId();
  await env.DB.batch(insertImageStmts(env, id, "site", img.mime, img.buf));
  return json({ ok: true, id });
}

async function adminImageDelete(req, env) {
  const b = await req.json();
  if (ID_RE.test(String(b.id))) {
    const r = await env.DB.prepare("SELECT 1 AS x FROM images WHERE id = ? AND kind = 'site'").bind(b.id).first();
    if (r) await env.DB.batch(deleteImageStmts(env, b.id));
  }
  return json({ ok: true });
}


/* ---------- รายชื่อพื้นที่ (แก้ได้ทุกปีตามประเทศเจ้าภาพ) ---------- */
async function adminRegions(req, env) {
  const b = await req.json();
  const prev = await getRegions(env);
  const lines = String(b.text || "").replace(/\r/g, "").split("\n").map((l) => l.trim().replace(/\s+/g, " ").slice(0, 60)).filter(Boolean);
  if (!lines.length) return fail(400, "empty", "ต้องมีอย่างน้อย 1 พื้นที่");
  if (lines.length > 300) return fail(400, "too_many", "ใส่ได้ไม่เกิน 300 พื้นที่");
  const used = new Set(), out = [];
  for (const name of lines) {
    if (out.some((r) => r.name.toLowerCase() === name.toLowerCase())) continue; // ตัดชื่อซ้ำ
    const old = prev.find((r) => r.name.toLowerCase() === name.toLowerCase());
    let slug = old ? old.slug : slugify(name) || "r-" + randId().slice(0, 8);
    while (used.has(slug)) slug += "-" + randId().slice(0, 3);
    used.add(slug); out.push({ slug, name });
  }
  await kvSet(env, "regions", out).run();
  memo = null;
  return json({ ok: true, regions: out });
}

/* ---------- router ---------- */
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;
    try {
      if (p.startsWith("/img/")) return await serveImage(req, env, p.slice(5));
      if (!p.startsWith("/api/")) return env.ASSETS.fetch(req);
      const ip = req.headers.get("cf-connecting-ip") || "local";
      const post = req.method === "POST";

      if (p === "/api/state" && req.method === "GET") return await apiState(req, env);
      if (p === "/api/claim" && post) return await apiClaim(req, env, ip);
      if (p === "/api/photo" && post) return await apiPhoto(req, env);
      if (p === "/api/slip" && post) return await apiSlip(req, env);
      if (p === "/api/admin/login" && post) return await adminLogin(req, env);
      if (p === "/api/admin/logout" && post) return json({ ok: true }, 200, { "set-cookie": "mm_admin=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict" });

      if (p.startsWith("/api/admin/")) {
        if (!(await isAdmin(req, env))) return fail(401, "unauthorized", "ต้องเข้าสู่ระบบแอดมิน");
        if (p === "/api/admin/list" && req.method === "GET") return await adminList(env);
        if (p === "/api/admin/regions" && post) return await adminRegions(req, env);
        if (p === "/api/admin/review" && post) return await adminReview(req, env);
        if (p === "/api/admin/release" && post) return await adminRelease(req, env);
        if (p === "/api/admin/settings" && post) return await adminSettings(req, env);
        if (p === "/api/admin/content" && post) return await adminContent(req, env);
        if (p === "/api/admin/image" && post) return await adminImage(req, env);
        if (p === "/api/admin/image-delete" && post) return await adminImageDelete(req, env);
      }
      return fail(404, "not_found", "ไม่พบ");
    } catch (e) {
      return fail(500, "server", String((e && e.message) || e));
    }
  },
};
