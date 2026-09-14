// ===========================================================================
// Get your CloudGate tokens from the browser console.
//
// HOW TO USE:
//   1. Open the CloudGate web app and sign in (the tab must be on CloudGate's
//      own origin - that's where the session lives).
//   2. Open DevTools > Console.
//   3. Paste this whole file and press Enter.
//
// It reads the Firebase auth session your browser already stored for you,
// refreshes it once against Google's token endpoint, prints YOUR refresh token
// + a fresh ID token, and copies the refresh token to your clipboard. Nothing
// is uploaded anywhere - only you see the output. Treat the refresh token like
// a password.
// ===========================================================================
(async () => {
  const API_KEY = "AIzaSyB1RHsJMh5Rfv1qfLqQ0hg4ktCghj22Ss4"; // CloudGate's public Firebase key

  // Firebase v9+ persists the signed-in user in IndexedDB by default; older
  // persistence used localStorage. Try both.
  const fromIDB = () =>
    new Promise((resolve) => {
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

  const fromLocalStorage = () => {
    const out = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith("firebase:authUser:")) {
        try { out.push({ fbase_key: k, value: JSON.parse(localStorage.getItem(k)) }); } catch { /* skip */ }
      }
    }
    return out;
  };

  let records = await fromIDB();
  if (!records.length) records = fromLocalStorage();

  const rec = records.find((r) => (r.fbase_key || "").startsWith("firebase:authUser:"));
  if (!rec || !rec.value) {
    console.error(
      "%cNo CloudGate/Firebase session found on this origin.",
      "color:#f2695f;font-weight:bold"
    );
    console.error("Make sure you're signed into CloudGate in THIS tab, then run this again.");
    return;
  }

  const user = rec.value;
  const stm = user.stsTokenManager || {};
  const refreshToken = stm.refreshToken;
  let idToken = stm.accessToken; // cached; may be expired - we refresh below
  const email = user.email;

  if (!refreshToken) {
    console.error("Found a session but no refresh token in it - try signing out and back in.");
    return;
  }

  // The "requests" part: exchange the refresh token for a fresh ID token so you
  // get a known-good, non-expired one. This is the same call the client makes.
  try {
    const resp = await fetch(`https://securetoken.googleapis.com/v1/token?key=${API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }),
    });
    const data = await resp.json();
    if (resp.ok && data.id_token) {
      idToken = data.id_token;
      if (data.refresh_token) {
        // Google may hand back a rotated refresh token - prefer that one.
        rec.value.stsTokenManager.refreshToken = data.refresh_token;
      }
    } else {
      console.warn("Token refresh call failed, showing the cached ID token instead:", data.error || data);
    }
  } catch (e) {
    console.warn("Token refresh request errored, showing the cached ID token instead:", e.message);
  }

  const finalRefresh = rec.value.stsTokenManager.refreshToken || refreshToken;

  console.log("%cYour CloudGate tokens", "font-weight:bold;font-size:14px");
  console.log("%c(keep these secret - anyone with the refresh token can access your storage; nothing was uploaded)",
    "color:#a3a3b3");
  console.table({
    email,
    refresh_token: finalRefresh,
    id_token: idToken,
  });

  // Copy the refresh token to the clipboard so you can paste it straight into
  // the setup form. Tries the async Clipboard API, then DevTools' copy(), then
  // just leaves it on screen to copy by hand.
  let copied = false;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(finalRefresh);
      copied = true;
    }
  } catch { /* fall through */ }
  if (!copied && typeof copy === "function") {
    try { copy(finalRefresh); copied = true; } catch { /* fall through */ }
  }
  console.log(
    copied
      ? "%c✓ refresh token copied to your clipboard - paste it into the setup page"
      : "%c(couldn't auto-copy - select the refresh_token above and copy it manually)",
    copied ? "color:#34A853;font-weight:bold" : "color:#FBBC05"
  );
  console.log("Set this as CLOUDGATE_REFRESH_TOKEN in your own client:\n", finalRefresh);

  // Also returned so you can grab it programmatically from the console result.
  return { email, refresh_token: finalRefresh, id_token: idToken };
})();
