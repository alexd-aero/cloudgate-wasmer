// ===========================================================================
// CloudGate setup-code generator (run in your browser console).
//
// HOW TO USE:
//   1. Open the CloudGate web app and sign in (the tab must be on CloudGate's
//      own origin - that's where the session lives).
//   2. Open DevTools > Console.
//   3. Paste this whole file and press Enter.
//
// It reads the Firebase session your browser already stored, refreshes it, and
// copies ONE setup code to your clipboard - paste that into the app's /setup
// page and it fills in everything (email, refresh token, and a generated
// access key). Nothing is uploaded anywhere. Treat the code as a secret: it
// contains your refresh token.
// ===========================================================================
(async () => {
  const API_KEY = "AIzaSyB1RHsJMh5Rfv1qfLqQ0hg4ktCghj22Ss4"; // CloudGate's public Firebase key

  const fromIDB = () => new Promise((resolve) => {
    let open;
    try { open = indexedDB.open("firebaseLocalStorageDb"); } catch { return resolve([]); }
    open.onerror = () => resolve([]);
    open.onsuccess = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("firebaseLocalStorage")) return resolve([]);
      const req = db.transaction("firebaseLocalStorage", "readonly")
        .objectStore("firebaseLocalStorage").getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => resolve([]);
    };
  });
  const fromLS = () => {
    const out = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith("firebase:authUser:")) {
        try { out.push({ fbase_key: k, value: JSON.parse(localStorage.getItem(k)) }); } catch { /* skip */ }
      }
    }
    return out;
  };

  let recs = await fromIDB();
  if (!recs.length) recs = fromLS();
  const rec = recs.find((r) => (r.fbase_key || "").startsWith("firebase:authUser:"));
  if (!rec || !rec.value) {
    console.error("%cNo CloudGate session found on this origin.", "color:#f2695f;font-weight:bold");
    console.error("Sign into CloudGate in THIS tab, then run this again.");
    return;
  }

  const stm = rec.value.stsTokenManager || {};
  const email = rec.value.email;
  let refresh = stm.refreshToken;
  if (!refresh) { console.error("Session has no refresh token - sign out and back in."); return; }

  // Refresh once so we hand over a known-good token (and pick up a rotated one).
  try {
    const r = await fetch(`https://securetoken.googleapis.com/v1/token?key=${API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refresh }),
    });
    const d = await r.json();
    if (r.ok && d.refresh_token) refresh = d.refresh_token;
  } catch { /* keep cached token */ }

  // Generate the permanent access key (REAUTH_ACCESS_TOKEN) here so setup only
  // ever needs a username and password from you.
  const rnd = new Uint8Array(32);
  crypto.getRandomValues(rnd);
  const reauth = btoa(String.fromCharCode(...rnd)).replace(/=+$/, "");

  // Pack it all into one url-safe base64 code.
  const payload = { v: 1, email, refresh_token: refresh, reauth_token: reauth };
  const b64 = btoa(unescape(encodeURIComponent(JSON.stringify(payload))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const code = "CGSETUP1:" + b64;

  let copied = false;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(code);
      copied = true;
    }
  } catch { /* fall through */ }
  if (!copied && typeof copy === "function") {
    try { copy(code); copied = true; } catch { /* fall through */ }
  }

  console.log("%cCloudGate setup code" + (copied ? " (copied to clipboard)" : ""),
    "font-weight:bold;font-size:14px;color:#34A853");
  console.log("%cPaste it into your app's /setup page. Keep it secret - it holds your refresh token.",
    "color:#a3a3b3");
  console.log(code);
  if (!copied) console.log("%c(auto-copy blocked - select the code above and copy it manually)", "color:#FBBC05");

  return code;
})();
