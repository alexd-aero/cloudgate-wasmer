// Node.js/Express port of ../../app.py - same routes, same behavior, so the
// existing static/index.html + login.html frontend works unmodified against
// either backend.
import "./env-shim.js"; // must run before anything that touches os.homedir()
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
  res.set("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

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
