// Node.js/Express port of ../../app.py - same routes, same behavior, so the
// existing static/index.html + login.html frontend works unmodified against
// either backend.
import "./env-shim.js"; // must run before anything that touches os.homedir()
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import dotenv from "dotenv";
import express from "express";
import multer from "multer";
import {
  CloudGateClient,
  CloudGateAuthError,
  FIREBASE_API_KEY,
  FIREBASE_PROJECT_ID,
  isValidCategoryId,
  isTextFile,
  aceMode,
} from "./cloudgate.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, "..", ".env") });
const upload = multer({ storage: multer.memoryStorage() });

const app = express();
app.use(express.json());

// Personal single-user API, no cookie/session auth to leak - safe to allow
// any origin so standalone tools/test pages can call it directly.
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Optional global gate. If CREDENTIALS is set, require login before anything -
// this keeps the whole app private, including the /api/* routes below that
// operate on the owner's storage with no auth of their own (browse/upload/
// download/delete). Without it, anyone who finds the deployed URL can read and
// delete the owner's files.
//
// It uses a cookie-backed login page rather than HTTP Basic Auth: Basic Auth
// makes the browser re-pop its native dialog on redirects/new tabs/subresources
// (and sometimes twice on first load), which is the behaviour we're fixing. A
// signed cookie is sent automatically and silently on every request instead.
// A preemptive `Authorization: Basic user:pass` header is still accepted so
// curl/scripts keep working; we just never send a WWW-Authenticate challenge,
// so no browser dialog ever appears.
//
// Format (set it in app.yaml env or Wasmer > Settings > Environment Variables):
//   CREDENTIALS = "user","pass"
// Leave CREDENTIALS unset to disable the gate (fails open, for local dev).
function parseCredentials() {
  const raw = (process.env.CREDENTIALS || "").trim();
  const m = raw.match(/^"([^"]*)"\s*,\s*"([^"]*)"$/);
  return m ? { user: m[1], pass: m[2] } : null;
}
const CREDS = parseCredentials();
if (process.env.CREDENTIALS && !CREDS) {
  console.warn('CREDENTIALS is set but not in the form "user","pass" - login gate is DISABLED');
}

// length-independent constant-time string compare (avoids leaking length/
// content via timing; timingSafeEqual itself requires equal-length buffers)
function safeEqual(a, b) {
  const ah = crypto.createHash("sha256").update(String(a)).digest();
  const bh = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ah, bh);
}

// Cookie proof-of-login. It's a stable HMAC of the credentials under a server
// secret, so no session store is needed; anyone without the exact CREDENTIALS
// can't forge it. Keyed on REAUTH_ACCESS_TOKEN (or the creds themselves) so it
// stays valid across restarts.
const GATE_SECRET =
  process.env.REAUTH_ACCESS_TOKEN || process.env.CREDENTIALS || crypto.randomBytes(32).toString("hex");
function gateToken() {
  return crypto.createHmac("sha256", GATE_SECRET)
    .update("cg-gate-v1|" + (CREDS ? CREDS.user : "")).digest("hex");
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function hasValidCookie(req) {
  const c = parseCookies(req).cg_gate;
  if (!c) return false;
  const good = gateToken();
  return c.length === good.length && crypto.timingSafeEqual(Buffer.from(c), Buffer.from(good));
}
function hasValidBasic(req) {
  const hdr = req.headers.authorization || "";
  if (!hdr.startsWith("Basic ")) return false;
  let d = "";
  try { d = Buffer.from(hdr.slice(6), "base64").toString("utf-8"); } catch { return false; }
  const i = d.indexOf(":");
  return i >= 0 && safeEqual(d.slice(0, i), CREDS.user) && safeEqual(d.slice(i + 1), CREDS.pass);
}
// keep a redirect target local (no open-redirect to other sites)
function safeNext(next) {
  return typeof next === "string" && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}

if (CREDS) {
  app.use((req, res, next) => {
    if (req.method === "OPTIONS") return next();
    if (req.path === "/gate" || req.path === "/gate/login") return next(); // login endpoints
    if (hasValidCookie(req) || hasValidBasic(req)) return next();
    // Not authed. Redirect real page loads to the login page; answer everything
    // else with 401 JSON. No WWW-Authenticate header -> no native browser popup.
    if (req.method === "GET" && (req.headers.accept || "").includes("text/html")) {
      return res.redirect(302, "/gate?next=" + encodeURIComponent(req.originalUrl || "/"));
    }
    return res.status(401).json({ error: "auth_required" });
  });

  app.get("/gate", (req, res) => {
    res.type("html").send(gatePageHtml(safeNext(req.query.next)));
  });
  app.post("/gate/login", (req, res) => {
    const { user, pass } = req.body || {};
    if (typeof user === "string" && typeof pass === "string" &&
        safeEqual(user, CREDS.user) && safeEqual(pass, CREDS.pass)) {
      res.append("Set-Cookie",
        `cg_gate=${gateToken()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000; Secure`);
      return res.json({ ok: true });
    }
    return res.status(401).json({ error: "invalid credentials" });
  });
}

function gatePageHtml(next) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Sign in</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--bg:#0a0a10;--glass:rgba(255,255,255,.06);--bd:rgba(255,255,255,.14);--text:#f4f4f8;
--dim:#9a9aac;--accent:#7c6df2;--danger:#f2695f}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:radial-gradient(1000px 500px at 80% -10%,#17172a,var(--bg) 60%);color:var(--text);
display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:360px;max-width:92vw;background:var(--glass);border:1px solid var(--bd);
border-radius:18px;padding:30px 26px;backdrop-filter:blur(20px);box-shadow:0 8px 32px rgba(0,0,0,.35)}
.logo{width:46px;height:46px;border-radius:13px;margin:0 auto 16px;display:flex;align-items:center;
justify-content:center;font-size:21px;color:#fff;background:linear-gradient(140deg,#4285F4,#A142F4)}
h1{font-size:18px;margin:0 0 18px;text-align:center}
input{width:100%;background:rgba(0,0,0,.32);color:var(--text);border:1px solid var(--bd);
border-radius:10px;padding:11px 13px;font-size:14px;margin-bottom:12px}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(124,109,242,.16)}
button{width:100%;background:var(--accent);color:#fff;border:none;border-radius:10px;padding:12px;
font-size:14px;font-weight:600;cursor:pointer}button:disabled{opacity:.6}
#err{color:var(--danger);font-size:12.5px;min-height:16px;margin-top:10px;text-align:center}
</style></head><body>
<form class="card" id="f">
<div class="logo">&#128274;</div><h1>Sign in to CloudGate</h1>
<input id="u" placeholder="Username" autocomplete="username" autofocus>
<input id="p" type="password" placeholder="Password" autocomplete="current-password">
<button type="submit">Sign in</button><div id="err"></div>
</form>
<script>
var NEXT=${JSON.stringify(next)};
document.getElementById("f").addEventListener("submit",async function(e){
  e.preventDefault();var b=e.target.querySelector("button");var err=document.getElementById("err");
  b.disabled=true;err.textContent="";
  try{
    var r=await fetch("/gate/login",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({user:document.getElementById("u").value,pass:document.getElementById("p").value})});
    if(!r.ok){err.textContent="Wrong username or password.";b.disabled=false;return;}
    window.location.href=NEXT||"/";
  }catch(_){err.textContent="Something went wrong. Try again.";b.disabled=false;}
});
</script></body></html>`;
}

app.use(express.static(path.join(__dirname, "..", "public")));

const client = new CloudGateClient();

function fileJson(f) {
  return {
    key: f.key,
    filename: f.filename,
    size: f.size,
    last_modified: f.lastModified,
    category: f.category,
    folder_path: f.folderPath,
    url: f.url,
    download_url: `/api/download?key=${encodeURIComponent(f.key)}`,
    stream_path: `/api/stream/${encodeURIComponent(f.filename)}?key=${encodeURIComponent(f.key)}`,
    is_text: isTextFile(f.filename),
    ace_mode: aceMode(f.filename),
  };
}

// wraps an async route handler so thrown errors (incl. CloudGateAuthError)
// reach the error middleware instead of crashing the process
const h = (fn) => (req, res, next) => fn(req, res, next).catch(next);

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "..", "public", "index.html")));

// First-run setup: capture your CloudGate token and generate the env config to
// paste into app.yaml. Static middleware also serves this at /setup.html; this
// is just a cleaner URL. Runs client-side only - it stores nothing server-side.
app.get("/setup", (req, res) => res.sendFile(path.join(__dirname, "..", "public", "setup.html")));

// /login is gated behind REAUTH_ACCESS_TOKEN: a public "Sign in with Google"
// page with no gate is indistinguishable from an OAuth-phishing page to
// automated abuse scanners (and to any stranger who finds the link) - it
// invites anyone to grant a Google consent screen before this app ever gets
// a chance to check whose account it is. Requiring a secret token in the
// URL means only someone who already has it can reach the page at all.
function requireReauthToken(req, res, next) {
  const required = process.env.REAUTH_ACCESS_TOKEN;
  if (!required) return res.status(404).send("Not found");
  if (req.query.token !== required) return res.status(404).send("Not found");
  next();
}

app.get("/login", requireReauthToken, (req, res) => res.sendFile(path.join(__dirname, "..", "public", "login.html")));

app.get("/api/login-config", requireReauthToken, (req, res) => {
  res.json({ apiKey: FIREBASE_API_KEY, projectId: FIREBASE_PROJECT_ID });
});

app.post(
  "/api/reauth",
  requireReauthToken,
  h(async (req, res) => {
    const { email, refresh_token: refreshToken } = req.body || {};
    if (!refreshToken || !email) return res.status(400).json({ error: "missing refresh_token or email" });
    if (email.toLowerCase() !== client.email.toLowerCase()) {
      return res.status(400).json({ error: `signed in as ${email}, expected ${client.email}` });
    }
    try {
      await client.reauth(refreshToken);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }
    res.json({ ok: true });
  })
);

app.get(
  "/api/profile",
  h(async (req, res) => res.json(await client.profile()))
);

app.get(
  "/api/stats",
  h(async (req, res) => res.json(await client.storageStats()))
);

app.get(
  "/api/quota",
  h(async (req, res) => {
    const q = await client.quota();
    res.json({ used_bytes: q.usedBytes, total_bytes: q.totalBytes, plan: q.plan });
  })
);

app.get(
  "/api/all-files",
  h(async (req, res) => res.json((await client.listAllFiles()).map(fileJson)))
);

app.get(
  "/api/categories",
  h(async (req, res) => res.json(await client.listCategories()))
);

app.post(
  "/api/categories",
  h(async (req, res) => {
    const id = (req.body.id || "").trim().toLowerCase();
    if (!isValidCategoryId(id)) {
      return res.status(400).json({ error: "category id must be lowercase letters/numbers/-/_ only" });
    }
    try {
      await client.createCategory(id, req.body.label, req.body.icon, req.body.color);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }
    res.json({ ok: true });
  })
);

app.delete(
  "/api/categories",
  h(async (req, res) => {
    const id = req.body.id;
    if (!id) return res.status(400).json({ error: "missing id" });
    try {
      await client.deleteCategory(id);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }
    res.json({ ok: true });
  })
);

app.get(
  "/api/browse",
  h(async (req, res) => {
    const { category, path: subPath = "" } = req.query;
    if (!isValidCategoryId(category)) return res.status(400).json({ error: "invalid category" });
    const { folders, files } = await client.browse(category, subPath);
    res.json({ folders, files: files.map(fileJson) });
  })
);

app.post(
  "/api/folders",
  h(async (req, res) => {
    const { category, path: subPath = "" } = req.body;
    const name = (req.body.name || "").trim();
    if (!isValidCategoryId(category) || !name || name.includes("/")) {
      return res.status(400).json({ error: "invalid category or folder name" });
    }
    await client.createFolder(category, subPath, name);
    res.json({ ok: true });
  })
);

app.post(
  "/api/folders/rename",
  h(async (req, res) => {
    const { category, path: subPath = "" } = req.body;
    const oldName = (req.body.old_name || "").trim();
    const newName = (req.body.new_name || "").trim();
    if (!isValidCategoryId(category) || !oldName || !newName || newName.includes("/")) {
      return res.status(400).json({ error: "invalid rename request" });
    }
    await client.renameFolder(category, subPath, oldName, newName);
    res.json({ ok: true });
  })
);

app.delete(
  "/api/folders",
  h(async (req, res) => {
    const { category, path: subPath = "", name } = req.body;
    if (!isValidCategoryId(category) || !name) return res.status(400).json({ error: "invalid delete request" });
    await client.deleteFolder(category, subPath, name);
    res.json({ ok: true });
  })
);

app.post(
  "/api/upload",
  upload.single("file"),
  h(async (req, res) => {
    const { category, path: subPath = "" } = req.body;
    if (!isValidCategoryId(category)) return res.status(400).json({ error: "invalid category" });
    if (!req.file) return res.status(400).json({ error: "missing file" });
    const result = await client.uploadFile(req.file.buffer, category, subPath, req.file.originalname);
    res.json(fileJson(result));
  })
);

// Preferred upload path: get a presigned URL, then PUT the file straight to
// S3 from the browser - the actual bytes never pass through this server, so
// it isn't bounded by the serverless function's execution time or memory.
app.post(
  "/api/upload/presign",
  h(async (req, res) => {
    const { category, path: subPath = "", filename } = req.body;
    if (!isValidCategoryId(category) || !filename) {
      return res.status(400).json({ error: "invalid category or filename" });
    }
    const result = await client.presignUpload(category, subPath, filename);
    res.json(result);
  })
);

// Chunked/parallel upload (multipart). create -> browser PUTs parts
// concurrently -> complete.
const MULTIPART_PART_SIZE = 6 * 1024 * 1024; // 6 MB (S3 minimum part size is 5 MB)

app.post(
  "/api/upload/multipart/create",
  h(async (req, res) => {
    const { category, path: subPath = "", filename, size } = req.body;
    if (!isValidCategoryId(category) || !filename || !Number.isFinite(size)) {
      return res.status(400).json({ error: "invalid category, filename or size" });
    }
    const result = await client.createMultipartUpload(category, subPath, filename, size, MULTIPART_PART_SIZE);
    res.json(result);
  })
);

app.post(
  "/api/upload/multipart/complete",
  h(async (req, res) => {
    const { key, uploadId } = req.body;
    if (!key || !uploadId) return res.status(400).json({ error: "missing key or uploadId" });
    const result = await client.completeMultipartUpload(key, uploadId);
    res.json(fileJson(result));
  })
);

app.post(
  "/api/upload/multipart/abort",
  h(async (req, res) => {
    const { key, uploadId } = req.body;
    if (!key || !uploadId) return res.status(400).json({ error: "missing key or uploadId" });
    await client.abortMultipartUpload(key, uploadId);
    res.json({ ok: true });
  })
);

app.get(
  "/api/files/exists",
  h(async (req, res) => {
    const key = req.query.key;
    if (!key) return res.status(400).json({ error: "missing key" });
    const size = await client.objectExists(key);
    res.json({ exists: size !== null, size });
  })
);

app.post(
  "/api/files/rename",
  h(async (req, res) => {
    const { key } = req.body;
    const newName = (req.body.new_name || "").trim();
    if (!key || !newName || newName.includes("/")) return res.status(400).json({ error: "invalid rename request" });
    const result = await client.renameFile(key, newName);
    res.json(fileJson(result));
  })
);

app.delete(
  "/api/files",
  h(async (req, res) => {
    const key = req.body && req.body.key;
    if (!key) return res.status(400).json({ error: "missing key" });
    await client.deleteFile(key);
    res.json({ ok: true });
  })
);

app.get(
  "/api/download",
  h(async (req, res) => {
    const key = req.query.key;
    if (!key) return res.status(400).json({ error: "missing key" });
    const { buffer, contentType } = await client.getObjectBytes(key);
    const filename = key.split("/").pop();
    res.set("Content-Type", contentType);
    res.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
    res.send(buffer);
  })
);

app.get("/api/stream/:filename", (req, res) => {
  const key = req.query.key;
  if (!key) return res.status(400).json({ error: "missing key" });
  res.redirect(302, client.publicUrl(key));
});

app.get(
  "/api/files/content",
  h(async (req, res) => {
    const key = req.query.key;
    if (!key) return res.status(400).json({ error: "missing key" });
    res.json({ content: await client.getText(key) });
  })
);

app.put(
  "/api/files/content",
  h(async (req, res) => {
    const { key, content } = req.body;
    if (!key || content === undefined || content === null) {
      return res.status(400).json({ error: "missing key or content" });
    }
    const result = await client.putText(key, content);
    res.json(fileJson(result));
  })
);

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof CloudGateAuthError) {
    return res.status(401).json({ error: "reauth_required", detail: err.message });
  }
  console.error(err);
  res.status(500).json({ error: err.message || "internal error" });
});

const PORT = process.env.PORT || 5058;
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  app.listen(PORT, () => console.log(`CloudGate client (Node) listening on :${PORT}`));
}

export default app;
