// FANNY BACKEND TAHAP 1
// Cloudflare Worker + D1
// Endpoint:
// POST /api/auth/register
// POST /api/auth/login
// POST /api/auth/logout
// GET  /api/auth/me
// GET  /api/admin/users

const encoder = new TextEncoder();

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
      ...extra
    }
  });
}

function base64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function bytesFromBase64(s) {
  const b = atob(s);
  return Uint8Array.from(b, c => c.charCodeAt(0));
}

function randomBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

async function sha256(input) {
  const data = typeof input === "string" ? encoder.encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function passwordHash(password, saltB64) {
  const salt = saltB64 ? bytesFromBase64(saltB64) : randomBytes(16);

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return {
    salt: base64(salt),
    hash: base64(new Uint8Array(bits))
  };
}

function cookie(request) {
  const header = request.headers.get("Cookie") || "";
  for (const item of header.split(";")) {
    const [key, ...rest] = item.trim().split("=");
    if (key === "fanny_session") return decodeURIComponent(rest.join("="));
  }
  return null;
}

function setSession(token) {
  return [
    `fanny_session=${encodeURIComponent(token)}`,
    "Path=/",
    "Max-Age=604800",
    "HttpOnly",
    "Secure",
    "SameSite=Lax"
  ].join("; ");
}

async function createSession(env, userId) {
  const raw = base64(randomBytes(32))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

  const hash = await sha256(raw);
  const id = crypto.randomUUID();
  const expires = Math.floor(Date.now() / 1000) + 604800;

  await env.DB.prepare(
    "INSERT INTO sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,?)"
  ).bind(id, userId, hash, expires).run();

  return raw;
}

async function currentUser(request, env) {
  const token = cookie(request);
  if (!token) return null;

  const hash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  return await env.DB.prepare(`
    SELECT u.id,u.name,u.email,u.role,u.balance,u.status,u.created_at
    FROM sessions s
    JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at>? AND u.status='active'
    LIMIT 1
  `).bind(hash, now).first();
}

function emailOK(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function register(request, env) {
  const body = await request.json();
  const name = String(body.name || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (name.length < 2 || name.length > 80)
    return json({ok:false,message:"Nama harus 2-80 karakter."},400);

  if (!emailOK(email))
    return json({ok:false,message:"Email tidak valid."},400);

  if (password.length < 8 || password.length > 128)
    return json({ok:false,message:"Password harus 8-128 karakter."},400);

  const exists = await env.DB.prepare(
    "SELECT id FROM users WHERE email=? LIMIT 1"
  ).bind(email).first();

  if (exists)
    return json({ok:false,message:"Email sudah terdaftar."},409);

  const id = crypto.randomUUID();
  const p = await passwordHash(password);

  await env.DB.prepare(`
    INSERT INTO users
    (id,name,email,password_hash,password_salt)
    VALUES (?,?,?,?,?)
  `).bind(id,name,email,p.hash,p.salt).run();

  const token = await createSession(env,id);

  return json({
    ok:true,
    message:"Akun berhasil dibuat.",
    user:{id,name,email,role:"user",balance:0}
  },201,{"Set-Cookie":setSession(token)});
}

async function login(request, env) {
  const body = await request.json();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  const user = await env.DB.prepare(`
    SELECT id,name,email,role,balance,status,password_hash,password_salt
    FROM users WHERE email=? LIMIT 1
  `).bind(email).first();

  if (!user || user.status !== "active")
    return json({ok:false,message:"Email atau password salah."},401);

  const p = await passwordHash(password,user.password_salt);

  if (p.hash !== user.password_hash)
    return json({ok:false,message:"Email atau password salah."},401);

  const token = await createSession(env,user.id);

  return json({
    ok:true,
    message:"Login berhasil.",
    user:{
      id:user.id,name:user.name,email:user.email,
      role:user.role,balance:user.balance
    }
  },200,{"Set-Cookie":setSession(token)});
}

async function logout(request, env) {
  const token = cookie(request);
  if (token) {
    const hash = await sha256(token);
    await env.DB.prepare(
      "DELETE FROM sessions WHERE token_hash=?"
    ).bind(hash).run();
  }

  return json({ok:true,message:"Logout berhasil."},200,{
    "Set-Cookie":"fanny_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
  });
}

async function me(request, env) {
  const user = await currentUser(request,env);
  if (!user) return json({ok:false,authenticated:false},401);

  return json({
    ok:true,
    authenticated:true,
    user:{
      id:user.id,name:user.name,email:user.email,
      role:user.role,balance:user.balance,
      status:user.status,created_at:user.created_at
    }
  });
}

async function adminUsers(request, env) {
  const admin = await currentUser(request,env);

  if (!admin) return json({ok:false,message:"Belum login."},401);
  if (admin.role !== "admin")
    return json({ok:false,message:"Akses admin diperlukan."},403);

  const result = await env.DB.prepare(`
    SELECT id,name,email,role,balance,status,created_at
    FROM users ORDER BY created_at DESC LIMIT 100
  `).all();

  return json({ok:true,users:result.results || []});
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (request.method === "POST" && url.pathname === "/api/auth/register")
        return await register(request,env);

      if (request.method === "POST" && url.pathname === "/api/auth/login")
        return await login(request,env);

      if (request.method === "POST" && url.pathname === "/api/auth/logout")
        return await logout(request,env);

      if (request.method === "GET" && url.pathname === "/api/auth/me")
        return await me(request,env);

      if (request.method === "GET" && url.pathname === "/api/admin/users")
        return await adminUsers(request,env);

      return json({ok:false,message:"Endpoint tidak ditemukan."},404);
    } catch (error) {
      console.error(error);
      return json({ok:false,message:"Terjadi kesalahan server."},500);
    }
  }
};
