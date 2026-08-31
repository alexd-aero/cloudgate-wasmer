// Node.js port of ../../cloudgate.py - same reverse-engineered CloudGate
// auth chain (Firebase refresh token -> Firebase ID token -> AWS Cognito
// Identity Pool federated credentials -> signed S3 requests), so this can
// run as a Wasmer serverless Node.js app instead of the Python/Flask one.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  S3Client,
  ListObjectsV2Command,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  CopyObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import {
  CognitoIdentityClient,
  GetIdCommand,
  GetCredentialsForIdentityCommand,
} from "@aws-sdk/client-cognito-identity";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const FIREBASE_API_KEY = "AIzaSyB1RHsJMh5Rfv1qfLqQ0hg4ktCghj22Ss4";
export const FIREBASE_PROJECT_ID = "cloud-gate-a2282";
const COGNITO_IDENTITY_POOL_ID = "us-east-1:0efa4696-c52b-437e-a3ef-30694d15bacc";
const AWS_REGION = "us-east-1";
const S3_BUCKET = "dev-cloudgatebucket04439-dev";
const CLOUDFRONT_DOMAIN = "d1dncmkdpaif79.cloudfront.net";
const APPSYNC_ENDPOINT = "https://d2g6ylbwdzd6nccvg4zwni46ry.appsync-api.us-east-1.amazonaws.com/graphql";
const APPSYNC_API_KEY = "da2-awzt5u5yszhbhdbq655ustc2c4";
const BUCKET_META_ENDPOINT = "https://0ml0hbqu95.execute-api.us-east-1.amazonaws.com/prod/api/storage/bucketMetaData";

export const BUILTIN_CATEGORY_META = {
  image: { label: "Photos", icon: "fa-solid fa-image", color: "#4285F4" },
  video: { label: "Videos", icon: "fa-solid fa-film", color: "#EA4335" },
  audio: { label: "Music", icon: "fa-solid fa-music", color: "#34A853" },
  document: { label: "Documents", icon: "fa-solid fa-file-lines", color: "#FBBC05" },
  contact: { label: "Contacts", icon: "fa-solid fa-address-book", color: "#A142F4" },
  albums: { label: "Albums", icon: "fa-solid fa-images", color: "#24C1E0" },
  ios_apps: { label: "iOS Apps", icon: "fa-solid fa-mobile-screen-button", color: "#8ab4f8" },
};

const RESERVED_FOLDERS = new Set(["ThumbnailImages", "ThumbnailVideos"]);

// Storage: on Wasmer's serverless FS, writes may not persist across cold
// starts/instances - set CLOUDGATE_STATE_DIR to a mounted volume in
// production. Defaults to this directory for local/dev use.
const STATE_DIR = process.env.CLOUDGATE_STATE_DIR || __dirname;
const CREDENTIALS_PATH = path.join(STATE_DIR, "credentials.json");
const CUSTOM_CATEGORIES_PATH = path.join(STATE_DIR, "custom_categories.json");

const CATEGORY_ID_RE = /^[a-z0-9_-]{1,40}$/;
export function isValidCategoryId(id) {
  return typeof id === "string" && CATEGORY_ID_RE.test(id);
}

export class CloudGateAuthError extends Error {}

function loadJson(filePath) {
  if (!fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}
function saveJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
}

// mimetypes' builtin table misses (or mis-detects) most source-code/config
// extensions, and getting this wrong is exactly what makes text/code files
// download instead of rendering as raw text.
const CODE_TEXT_EXTENSIONS = new Set([
  ".txt", ".md", ".markdown", ".py", ".java", ".c", ".h", ".cpp", ".hpp",
  ".cs", ".go", ".rs", ".rb", ".php", ".sh", ".bash", ".zsh", ".ps1",
  ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".sql", ".log",
  ".env", ".r", ".swift", ".kt", ".kts", ".lua", ".pl", ".vue", ".svelte",
  ".jsx", ".tsx", ".ts", ".js", ".mjs", ".json", ".jsonc", ".xml", ".css",
  ".scss", ".less", ".html", ".htm", ".csv", ".tsv", ".dockerfile",
  ".gitignore", ".gitattributes", ".ovpn", ".pem", ".crt", ".key", ".pub",
  ".properties", ".rc",
]);
const SPECIAL_TEXT_FILENAMES = new Set([
  "dockerfile", "makefile", "procfile", "gemfile", "rakefile",
  "gitignore", "gitattributes", "gitmodules", "dockerignore",
  "npmignore", "editorconfig", "env", "eslintrc", "prettierrc",
  "babelrc", "npmrc", "yarnrc", "htaccess", "bashrc", "zshrc", "vimrc",
]);
const MIME_BY_EXTENSION = {
  ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif",
  ".webp": "image/webp", ".svg": "image/svg+xml", ".bmp": "image/bmp", ".ico": "image/x-icon",
  ".mp4": "video/mp4", ".mov": "video/quicktime", ".webm": "video/webm", ".mkv": "video/x-matroska",
  ".avi": "video/x-msvideo", ".mp3": "audio/mpeg", ".wav": "audio/wav", ".m4a": "audio/mp4",
  ".flac": "audio/flac", ".ogg": "audio/ogg", ".pdf": "application/pdf", ".zip": "application/zip",
  ".doc": "application/msword",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xls": "application/vnd.ms-excel",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".ppt": "application/vnd.ms-powerpoint",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
};

const ACE_MODE_BY_EXTENSION = {
  ".py": "python", ".java": "java", ".c": "c_cpp", ".h": "c_cpp",
  ".cpp": "c_cpp", ".hpp": "c_cpp", ".cs": "csharp", ".go": "golang",
  ".rs": "rust", ".rb": "ruby", ".php": "php", ".sh": "sh", ".bash": "sh",
  ".zsh": "sh", ".ps1": "powershell", ".yml": "yaml", ".yaml": "yaml",
  ".toml": "toml", ".ini": "ini", ".sql": "sql", ".swift": "swift",
  ".kt": "kotlin", ".kts": "kotlin", ".lua": "lua", ".pl": "perl",
  ".vue": "html", ".svelte": "html", ".jsx": "javascript",
  ".tsx": "typescript", ".ts": "typescript", ".js": "javascript",
  ".mjs": "javascript", ".json": "json", ".jsonc": "json", ".xml": "xml",
  ".css": "css", ".scss": "scss", ".less": "less", ".html": "html",
  ".htm": "html", ".md": "markdown", ".markdown": "markdown", ".csv": "text",
  ".tsv": "text", ".txt": "text", ".log": "text", ".env": "sh",
  ".cfg": "ini", ".conf": "ini",
};

function extOf(filename) {
  const base = path.basename(filename);
  const i = base.lastIndexOf(".");
  return i <= 0 ? "" : base.slice(i).toLowerCase();
}
function isTextByName(filename) {
  const base = path.basename(filename);
  if (CODE_TEXT_EXTENSIONS.has(extOf(filename))) return true;
  return SPECIAL_TEXT_FILENAMES.has(base.replace(/^\.+/, "").toLowerCase());
}
export function isTextFile(filename) {
  return isTextByName(filename);
}
export function guessContentType(filename) {
  if (isTextByName(filename)) return "text/plain; charset=utf-8";
  return MIME_BY_EXTENSION[extOf(filename)] || "application/octet-stream";
}
export function aceMode(filename) {
  const ext = extOf(filename);
  if (ACE_MODE_BY_EXTENSION[ext]) return ACE_MODE_BY_EXTENSION[ext];
  const name = path.basename(filename).replace(/^\.+/, "").toLowerCase();
  if (name === "dockerfile") return "dockerfile";
  if (["bashrc", "zshrc", "env"].includes(name)) return "sh";
  return "text";
}

function filenameOf(key) {
  return key.split("/").pop();
}
function folderPathOf(key, category) {
  const marker = `/${category}/`;
  const idx = key.indexOf(marker);
  const rest = key.slice(idx + marker.length);
  const parts = rest.split("/");
  parts.pop();
  return parts.join("/");
}
function publicUrlOf(key) {
  return `https://${CLOUDFRONT_DOMAIN}/${encodeURIComponent(key).replace(/%2F/g, "/")}`;
}

function toFileObject(key, size, lastModified, category) {
  return {
    key,
    size,
    lastModified: lastModified instanceof Date ? lastModified.toISOString() : lastModified,
    category,
    filename: filenameOf(key),
    folderPath: folderPathOf(key, category),
    url: publicUrlOf(key),
  };
}

async function streamToBuffer(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks);
}

export class CloudGateClient {
  constructor({ email, refreshToken, credentialsPath = CREDENTIALS_PATH } = {}) {
    this.credentialsPath = credentialsPath;
    const stored = credentialsPath ? loadJson(credentialsPath) : null;
    if (email && refreshToken) {
      this.email = email;
      this.refreshToken = refreshToken;
    } else if (stored) {
      this.email = email || stored.email;
      this.refreshToken = refreshToken || stored.refresh_token;
    } else {
      this.email = email || process.env.CLOUDGATE_EMAIL;
      this.refreshToken = refreshToken || process.env.CLOUDGATE_REFRESH_TOKEN;
      if (!this.email || !this.refreshToken) {
        throw new Error(
          "No CloudGate credentials found - set CLOUDGATE_EMAIL/CLOUDGATE_REFRESH_TOKEN env vars or provide credentials.json"
        );
      }
    }
    if (credentialsPath && !stored) this._persistCredentials();

    this._idToken = null;
    this._idTokenExp = 0;
    this._s3 = null;
    this._credsExp = 0;
  }

  _persistCredentials() {
    if (!this.credentialsPath) return;
    try {
      saveJson(this.credentialsPath, {
        email: this.email,
        refresh_token: this.refreshToken,
        updated_at: Date.now() / 1000,
      });
    } catch {
      /* best-effort */
    }
  }

  async _refreshIdToken() {
    if (this._idToken && Date.now() / 1000 < this._idTokenExp - 60) return this._idToken;

    const params = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: this.refreshToken,
    });
    let resp;
    try {
      resp = await fetch(`https://securetoken.googleapis.com/v1/token?key=${FIREBASE_API_KEY}`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params,
      });
      if (!resp.ok) throw new Error(`${resp.status} ${await resp.text()}`);
    } catch (e) {
      throw new CloudGateAuthError(`refresh token rejected: ${e.message}`);
    }
    const data = await resp.json();
    this._idToken = data.id_token;
    this._idTokenExp = Date.now() / 1000 + Number(data.expires_in);

    if (data.refresh_token !== this.refreshToken) {
      this.refreshToken = data.refresh_token;
      this._persistCredentials();
    }
    return this._idToken;
  }

  async reauth(refreshToken) {
    const old = { token: this.refreshToken, idToken: this._idToken, exp: this._idTokenExp };
    this.refreshToken = refreshToken;
    this._idToken = null;
    this._idTokenExp = 0;
    try {
      await this._refreshIdToken();
    } catch (e) {
      this.refreshToken = old.token;
      this._idToken = old.idToken;
      this._idTokenExp = old.exp;
      throw e;
    }
    this._persistCredentials();
  }

  async _s3Client() {
    if (this._s3 && Date.now() / 1000 < this._credsExp - 60) return this._s3;
    const idToken = await this._refreshIdToken();
    const logins = { [`securetoken.google.com/${FIREBASE_PROJECT_ID}`]: idToken };
    const cognito = new CognitoIdentityClient({ region: AWS_REGION });
    const { IdentityId } = await cognito.send(
      new GetIdCommand({ IdentityPoolId: COGNITO_IDENTITY_POOL_ID, Logins: logins })
    );
    const { Credentials } = await cognito.send(
      new GetCredentialsForIdentityCommand({ IdentityId, Logins: logins })
    );
    this._s3 = new S3Client({
      region: AWS_REGION,
      credentials: {
        accessKeyId: Credentials.AccessKeyId,
        secretAccessKey: Credentials.SecretKey,
        sessionToken: Credentials.SessionToken,
      },
    });
    this._credsExp = Credentials.Expiration.getTime() / 1000;
    return this._s3;
  }

  _prefix(category, subPath = "") {
    let prefix = `public/${this.email}/${category}/`;
    const trimmed = subPath.replace(/^\/+|\/+$/g, "");
    if (trimmed) prefix += trimmed + "/";
    return prefix;
  }

  // ---- categories ----
  async listCategories() {
    const custom = loadJson(CUSTOM_CATEGORIES_PATH) || {};
    const s3 = await this._s3Client();
    const rootPrefix = `public/${this.email}/`;
    const discovered = new Set();
    let token;
    do {
      const page = await s3.send(
        new ListObjectsV2Command({ Bucket: S3_BUCKET, Prefix: rootPrefix, Delimiter: "/", ContinuationToken: token })
      );
      for (const cp of page.CommonPrefixes || []) {
        discovered.add(cp.Prefix.slice(rootPrefix.length).replace(/\/$/, ""));
      }
      token = page.NextContinuationToken;
    } while (token);

    const ids = new Set([...Object.keys(BUILTIN_CATEGORY_META), ...Object.keys(custom), ...discovered]);
    const result = [...ids].map((id) => {
      const meta = BUILTIN_CATEGORY_META[id] || custom[id] || {};
      return {
        id,
        label: meta.label || id.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
        icon: meta.icon || "fa-solid fa-folder",
        color: meta.color || "#9aa0a6",
        custom: !BUILTIN_CATEGORY_META[id],
      };
    });
    result.sort((a, b) => Number(a.custom) - Number(b.custom) || a.label.localeCompare(b.label));
    return result;
  }

  async createCategory(id, label, icon, color) {
    if (!isValidCategoryId(id)) throw new Error("category id must be lowercase letters/numbers/-/_ only");
    if (BUILTIN_CATEGORY_META[id]) throw new Error("that category already exists");
    const custom = loadJson(CUSTOM_CATEGORIES_PATH) || {};
    custom[id] = {
      label: (label || "").trim() || id.replace(/_/g, " "),
      icon: (icon || "").trim() || "fa-solid fa-folder",
      color: (color || "").trim() || "#9aa0a6",
    };
    saveJson(CUSTOM_CATEGORIES_PATH, custom);
    const s3 = await this._s3Client();
    await s3.send(new PutObjectCommand({ Bucket: S3_BUCKET, Key: this._prefix(id), Body: "" }));
  }

  async deleteCategory(id) {
    if (BUILTIN_CATEGORY_META[id]) throw new Error("built-in categories can't be deleted");
    const custom = loadJson(CUSTOM_CATEGORIES_PATH) || {};
    delete custom[id];
    saveJson(CUSTOM_CATEGORIES_PATH, custom);
    await this._deletePrefix(this._prefix(id));
  }

  async _listKeysUnderPrefix(prefix) {
    const s3 = await this._s3Client();
    const keys = [];
    let token;
    do {
      const page = await s3.send(
        new ListObjectsV2Command({ Bucket: S3_BUCKET, Prefix: prefix, ContinuationToken: token })
      );
      for (const obj of page.Contents || []) keys.push(obj.Key);
      token = page.NextContinuationToken;
    } while (token);
    return keys;
  }

  async _deletePrefix(prefix) {
    const keys = await this._listKeysUnderPrefix(prefix);
    if (!keys.length) return;
    const s3 = await this._s3Client();
    for (let i = 0; i < keys.length; i += 1000) {
      const batch = keys.slice(i, i + 1000);
      await s3.send(
        new DeleteObjectsCommand({ Bucket: S3_BUCKET, Delete: { Objects: batch.map((Key) => ({ Key })) } })
      );
    }
  }

  // ---- browsing ----
  async browse(category, subPath = "") {
    if (!isValidCategoryId(category)) throw new Error("invalid category");
    const prefix = this._prefix(category, subPath);
    const s3 = await this._s3Client();
    const folders = [];
    const files = [];
    let token;
    do {
      const page = await s3.send(
        new ListObjectsV2Command({ Bucket: S3_BUCKET, Prefix: prefix, Delimiter: "/", ContinuationToken: token })
      );
      for (const cp of page.CommonPrefixes || []) {
        const name = cp.Prefix.slice(prefix.length).replace(/\/$/, "");
        if (!RESERVED_FOLDERS.has(name)) folders.push(name);
      }
      for (const obj of page.Contents || []) {
        if (obj.Key === prefix) continue;
        files.push(toFileObject(obj.Key, obj.Size, obj.LastModified, category));
      }
      token = page.NextContinuationToken;
    } while (token);
    folders.sort();
    return { folders, files };
  }

  async listAllFiles() {
    const categories = await this.listCategories();
    const files = [];
    for (const { id: category } of categories) {
      const prefix = this._prefix(category);
      const s3 = await this._s3Client();
      let token;
      do {
        const page = await s3.send(
          new ListObjectsV2Command({ Bucket: S3_BUCKET, Prefix: prefix, ContinuationToken: token })
        );
        for (const obj of page.Contents || []) {
          if (obj.Key === prefix || obj.Key.endsWith("/")) continue;
          const relParts = obj.Key.slice(prefix.length).split("/");
          relParts.pop();
          if (relParts.some((p) => RESERVED_FOLDERS.has(p))) continue;
          files.push(toFileObject(obj.Key, obj.Size, obj.LastModified, category));
        }
        token = page.NextContinuationToken;
      } while (token);
    }
    files.sort((a, b) => (a.lastModified < b.lastModified ? 1 : -1));
    return files;
  }

  async createFolder(category, subPath, name) {
    if (!isValidCategoryId(category)) throw new Error("invalid category");
    const key = `${this._prefix(category, subPath)}${name}/`;
    const s3 = await this._s3Client();
    await s3.send(new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, Body: "" }));
    return key;
  }

  async deleteFolder(category, subPath, name) {
    await this._deletePrefix(`${this._prefix(category, subPath)}${name}/`);
  }

  async renameFolder(category, subPath, oldName, newName) {
    const base = this._prefix(category, subPath);
    const oldPrefix = `${base}${oldName}/`;
    const newPrefix = `${base}${newName}/`;
    const oldKeys = await this._listKeysUnderPrefix(oldPrefix);
    const s3 = await this._s3Client();
    for (const oldKey of oldKeys) {
      const newKey = newPrefix + oldKey.slice(oldPrefix.length);
      await s3.send(
        new CopyObjectCommand({ Bucket: S3_BUCKET, CopySource: `${S3_BUCKET}/${encodeURIComponent(oldKey)}`, Key: newKey })
      );
    }
    if (oldKeys.length) {
      await s3.send(
        new DeleteObjectsCommand({ Bucket: S3_BUCKET, Delete: { Objects: oldKeys.map((Key) => ({ Key })) } })
      );
    }
  }

  // ---- files ----
  async uploadFile(buffer, category, subPath, remoteName) {
    if (!isValidCategoryId(category)) throw new Error("invalid category");
    const key = `${this._prefix(category, subPath)}${remoteName}`;
    const s3 = await this._s3Client();
    await s3.send(
      new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, Body: buffer, ContentType: guessContentType(remoteName) })
    );
    const head = await s3.send(new HeadObjectCommand({ Bucket: S3_BUCKET, Key: key }));
    return toFileObject(key, head.ContentLength, head.LastModified, category);
  }

  // Direct-to-S3 upload: the browser PUTs the file straight to S3 using a
  // short-lived presigned URL, never passing through this server at all.
  // Necessary for anything but small files on serverless - a function that
  // buffers the whole upload in memory first hits execution time/memory
  // limits on larger files (a lossless audio file was enough to trigger it).
  async presignUpload(category, subPath, remoteName) {
    if (!isValidCategoryId(category)) throw new Error("invalid category");
    const key = `${this._prefix(category, subPath)}${remoteName}`;
    const contentType = guessContentType(remoteName);
    const s3 = await this._s3Client();
    const command = new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, ContentType: contentType });
    const putUrl = await getSignedUrl(s3, command, { expiresIn: 300 });
    // publicUrl is for the client to verify completion afterward if its PUT
    // response never arrives (some browsers don't reliably fire the load
    // event for very large uploads even though the transfer succeeded) - a
    // presigned URL is signed for one specific method, so the PUT url can't
    // be reused for that HEAD check.
    return { putUrl, key, contentType, publicUrl: publicUrlOf(key) };
  }

  // Returns the object's size, or null if it isn't there (yet).
  async objectExists(key) {
    const s3 = await this._s3Client();
    try {
      const head = await s3.send(new HeadObjectCommand({ Bucket: S3_BUCKET, Key: key }));
      return head.ContentLength;
    } catch {
      return null;
    }
  }

  async renameFile(key, newName) {
    const newKey = key.slice(0, key.lastIndexOf("/") + 1) + newName;
    const s3 = await this._s3Client();
    await s3.send(
      new CopyObjectCommand({ Bucket: S3_BUCKET, CopySource: `${S3_BUCKET}/${encodeURIComponent(key)}`, Key: newKey })
    );
    await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: key }));
    const head = await s3.send(new HeadObjectCommand({ Bucket: S3_BUCKET, Key: newKey }));
    const category = key.split("/")[2];
    return toFileObject(newKey, head.ContentLength, head.LastModified, category);
  }

  async deleteFile(key) {
    const s3 = await this._s3Client();
    await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: key }));
  }

  async getObjectBytes(key) {
    const s3 = await this._s3Client();
    const obj = await s3.send(new GetObjectCommand({ Bucket: S3_BUCKET, Key: key }));
    const buffer = await streamToBuffer(obj.Body);
    const contentType = isTextByName(key) ? guessContentType(key) : obj.ContentType || guessContentType(key);
    return { buffer, contentType };
  }

  async getText(key) {
    const { buffer } = await this.getObjectBytes(key);
    return buffer.toString("utf-8");
  }

  async putText(key, content) {
    const s3 = await this._s3Client();
    await s3.send(
      new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, Body: Buffer.from(content, "utf-8"), ContentType: guessContentType(key) })
    );
    const head = await s3.send(new HeadObjectCommand({ Bucket: S3_BUCKET, Key: key }));
    const category = key.split("/")[2];
    return toFileObject(key, head.ContentLength, head.LastModified, category);
  }

  async fixContentType(key) {
    const guessed = guessContentType(key);
    const s3 = await this._s3Client();
    await s3.send(
      new CopyObjectCommand({
        Bucket: S3_BUCKET,
        CopySource: `${S3_BUCKET}/${encodeURIComponent(key)}`,
        Key: key,
        ContentType: guessed,
        MetadataDirective: "REPLACE",
      })
    );
    return guessed;
  }

  publicUrl(key) {
    return publicUrlOf(key);
  }

  // ---- metadata ----
  async storageStats() {
    const idToken = await this._refreshIdToken();
    const resp = await fetch(`${BUCKET_META_ENDPOINT}?user_folder=${encodeURIComponent(this.email)}`, {
      headers: { Authorization: `Bearer ${idToken}` },
    });
    if (!resp.ok) throw new Error(`bucketMetaData failed: ${resp.status}`);
    return resp.json();
  }

  async _graphql(operationName, variables, query) {
    const resp = await fetch(APPSYNC_ENDPOINT, {
      method: "POST",
      headers: { "X-Api-Key": APPSYNC_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ operationName, variables, query }),
    });
    if (!resp.ok) throw new Error(`AppSync failed: ${resp.status}`);
    const body = await resp.json();
    return body.data;
  }

  async profile() {
    const query = `query GetCloudGateMetaTable($id: ID!) {
      getCloudGateMetaTable(id: $id) {
        id userName userEmail userPhoneNumber gender token
        userDataPlan subscriptionProvider isEncryptionEnabled
        createdAt updatedAt
      }
    }`;
    const data = await this._graphql("GetCloudGateMetaTable", { id: this.email }, query);
    return data.getCloudGateMetaTable;
  }

  async planLimits() {
    const query = `query GetCloudGateDefaultSettingTable($id: ID!) {
      getCloudGateDefaultSettingTable(id: $id) {
        id appName FreePackage maxDataPackage monthlyPackage unlimitedPackage
      }
    }`;
    const data = await this._graphql("GetCloudGateDefaultSettingTable", { id: "CloudGate-Settings" }, query);
    return data.getCloudGateDefaultSettingTable;
  }

  async quota() {
    const [stats, limits, profile] = await Promise.all([this.storageStats(), this.planLimits(), this.profile()]);
    const used = Number(stats.total_size_bytes || 0);
    const plan = profile.userDataPlan || "FreePackage";
    const total = Number(limits[plan] || limits.FreePackage || 0);
    return { usedBytes: used, totalBytes: total, plan };
  }
}
