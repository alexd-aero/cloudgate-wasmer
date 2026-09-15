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
  // URL-safe base64 so REAUTH_ACCESS_TOKEN is safe to drop into the
  // ?token=... of the /login link (a raw '+' would decode to a space there).
  const reauth = btoa(String.fromCharCode(...rnd)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  // Pack it all into one url-safe base64 code.
  const payload = { v: 1, email, refresh_token: refresh, reauth_token: reauth };
  const b64 = btoa(unescape(encodeURIComponent(JSON.stringify(payload))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const code = "CGSETUP1:" + b64;

  // Clipboard writes from the console usually get blocked (they need a real
  // user gesture), which is why copying by hand was needed. Instead, drop a big
  // button onto the page - clicking it IS a gesture, so the copy just works.
  document.getElementById("__cg_setup_overlay")?.remove();
  const ov = document.createElement("div");
  ov.id = "__cg_setup_overlay";
  ov.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,.6);" +
    "display:flex;align-items:center;justify-content:center;" +
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif";
  const card = document.createElement("div");
  card.style.cssText = "background:#12121a;color:#f4f4f8;border:1px solid rgba(255,255,255,.15);" +
    "border-radius:16px;padding:26px;max-width:440px;width:90%;text-align:center;" +
    "box-shadow:0 20px 60px rgba(0,0,0,.55)";
  card.innerHTML = "<div style='font-size:19px;font-weight:700;margin-bottom:6px'>Setup code ready</div>" +
    "<div style='font-size:13px;color:#9a9aac;margin-bottom:20px'>Click to copy, then paste it into the setup page. Keep it secret - it holds your refresh token.</div>";
  const btn = document.createElement("button");
  btn.textContent = "Copy setup code";
  btn.style.cssText = "width:100%;padding:16px;font-size:16px;font-weight:700;border:none;" +
    "border-radius:12px;cursor:pointer;color:#fff;background:linear-gradient(135deg,#7c6df2,#a142f4)";
  const close = document.createElement("button");
  close.textContent = "Close";
  close.style.cssText = "margin-top:12px;background:none;border:none;color:#9a9aac;font-size:13px;cursor:pointer";
  close.onclick = () => ov.remove();
  btn.onclick = async () => {
    let ok = false;
    try { await navigator.clipboard.writeText(code); ok = true; } catch { /* fall through */ }
    if (!ok) {
      const ta = document.createElement("textarea");
      ta.value = code; ta.style.cssText = "position:fixed;opacity:0";
      document.body.appendChild(ta); ta.select();
      try { ok = document.execCommand("copy"); } catch { /* fall through */ }
      ta.remove();
    }
    btn.textContent = ok ? "Copied! Now paste it into the setup page" : "Copy failed - grab it from the console";
    btn.style.background = ok ? "#34A853" : "#d9534f";
    if (!ok) console.log(code);
  };
  card.appendChild(btn);
  card.appendChild(document.createElement("br"));
  card.appendChild(close);
  ov.appendChild(card);
  ov.addEventListener("click", (e) => { if (e.target === ov) ov.remove(); });
  document.body.appendChild(ov);

  console.log("%cCloudGate setup code ready - click the button on the page to copy it.",
    "font-weight:bold;font-size:14px;color:#34A853");
  console.log(code); // fallback if the button UI can't render
  return code;
})();
