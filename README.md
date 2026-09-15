# cloudgate-client (Node.js / Wasmer deployable)

A standalone, self-hostable client for **your own** CloudGate account. Deploy
it to Wasmer Edge (or run it locally) and you get a private web UI over your
CloudGate storage — browse, upload, download, edit and stream your files —
gated behind a username and password only you know.

It's a feature-identical Node.js/Express port of the Python/Flask client, kept
**Python-free on purpose** so Wasmer's build auto-detection runs it as a Node
app (`npm install` / `npm start`) with no manual overrides.

Everything connects to *your* account with *your* credentials. Nothing here
touches anyone else's data.

---

## Deploy it (the short version)

1. **Fork this repo, then make your fork private.** Forks start public and can't
   be made private until they leave the fork network first:
   [**fork it**](https://github.com/alexd-aero/cloudgate-wasmer/fork) →
   Settings → General → Danger Zone → **Leave fork network** → wait for the
   detach to finish (GitHub does it in the background, usually **2+ minutes**;
   the repo may 404 briefly) → then Danger Zone → **Change repository
   visibility → Private**. (Alternatively, skip the wait: create a fresh
   private repo and push these files into it.)
   Your credentials will be committed into `app.yaml`, so the repo **must** be
   private.
2. **Get your config from the `/setup` helper.** Open `public/setup.html` (or
   the `/setup` page of any running instance). It walks you through running the
   one-line console script in your CloudGate tab, pasting the resulting setup
   code, choosing a username/password, and copying a finished `app.yaml` `env:`
   block. Paste that into your fork's `app.yaml`, commit, and push.
3. **Deploy on Wasmer.** Dashboard → *Deploy → Import a Git repository* → pick
   your private fork. Node.js is auto-detected. **No environment variables need
   to be set in Wasmer** — they're already in `app.yaml`. Open your
   `*.wasmer.app` URL and log in with the username/password you chose.

That's it. Details below.

---

## The `/setup` page

Visit **`/setup`** on your deployment (or open `public/setup.html` locally). It
runs entirely in your browser and stores nothing on the server. Three steps:

1. **Run the script, click Copy.** Click **Copy script**, paste it into your
   CloudGate tab's DevTools console, and press Enter. It reads the session
   you're already signed into, refreshes it, and drops a big **Copy setup code**
   button onto the page — click it to copy a single **setup code** (a url-safe
   blob bundling your email, refresh token, and a freshly generated access key).
   Nothing is uploaded anywhere.
2. **Paste the code, pick a username & password.** Pasting the code auto-fills
   everything — email, refresh token, and the permanent access key. The *only*
   thing you enter by hand is the username and password that will gate the app.
3. **Copy your config & deploy.** It builds the `app.yaml` `env:` block (and a
   `.env`), each with a **Copy** button. Paste the block into your (private)
   repo, commit, and deploy.

The same setup-code script also lives at
[`get-cloudgate-token.console.js`](./get-cloudgate-token.console.js) if you'd
rather grab it from the repo.

> **Note:** `/setup` sits behind the same `CREDENTIALS` gate as the rest of the
> app once you've set it. On a fresh deploy (before `CREDENTIALS` is set) it's
> open so you can complete first-run setup; afterwards you'll log in first.

---

## Environment variables

| Variable | Required? | Format | Purpose |
| --- | --- | --- | --- |
| `CLOUDGATE_EMAIL` | yes | plain email | which account the client acts as |
| `CLOUDGATE_REFRESH_TOKEN` | yes | long token string | authenticates to your CloudGate storage |
| `CREDENTIALS` | strongly recommended | `"user","pass"` | login gate (cookie-based) over the **whole** app |
| `REAUTH_ACCESS_TOKEN` | recommended | random string | permanent secret that unlocks the `/login` re-auth page |
| `PORT` | no | number | listen port (Wasmer sets this; defaults to `5058`) |
| `CLOUDGATE_STATE_DIR` | no | path | persistent dir for token/category state, if your plan provides one |

### Where to put them

**Option A — in the repo (what `/setup` generates).** Add an `env:` block to
`app.yaml`. Mind the quoting — `CREDENTIALS` contains double quotes, so wrap it
in **single** quotes:

```yaml
env:
  CLOUDGATE_EMAIL: you@example.com
  CLOUDGATE_REFRESH_TOKEN: "AMf-vB...your-real-token..."
  REAUTH_ACCESS_TOKEN: "your-random-secret"
  CREDENTIALS: '"alex","a-long-random-password"'
```

Because this puts secrets in a file, **keep the repo private.**

**Option B — in Wasmer's dashboard.** App → *Settings → Environment Variables*.
Add the same four (for `CREDENTIALS` type `"user","pass"` with the quotes),
then redeploy. Keeps secrets out of git.

### `CREDENTIALS` — the app-wide gate

Format is two double-quoted strings separated by a comma: `"user","pass"`. When
set, **every** request — including all `/api/*` routes, which otherwise have no
auth and operate directly on your storage (browse/upload/**download/delete**) —
requires a login. Visitors get a `/gate` login page and, after signing in, a
signed `HttpOnly` cookie that's sent silently on every request (no repeated
browser popups on redirects or new tabs). Scripts can still authenticate by
sending a preemptive `Authorization: Basic user:pass` header (e.g.
`curl -u user:pass`). If `CREDENTIALS` is unset or malformed, the app logs a
warning and runs with **no gate at all**, so double-check the format.

### `REAUTH_ACCESS_TOKEN` — the permanent access token

A random secret you create (`openssl rand -base64 32`, or the *Generate* button
on `/setup`). It gates `/login`, the page you use to reconnect if your refresh
token ever stops working. A public, unauthenticated "Sign in with Google" page
is indistinguishable from an OAuth-phishing page to hosting providers' abuse
scanners (this app was disabled by Wasmer once for exactly that before the gate
existed) — so `/login` 404s for anyone without this token. It's *permanent* in
the sense that it doesn't rotate on its own; keep the full
`…/login?token=YOUR_REAUTH_ACCESS_TOKEN` URL somewhere private.

> This is **not** the short-lived `id_token` the capture script prints. That
> id_token expires in ~1 hour and is minted automatically from your refresh
> token — you never set it anywhere.

---

## Run locally

```bash
npm install
CLOUDGATE_EMAIL=you@example.com CLOUDGATE_REFRESH_TOKEN=... node src/server.js
```

Or create a `.env` (the `/setup` page generates one) and run `npm start`.
Defaults to port `5058` (`PORT` to change it). Open `http://localhost:5058/setup`.

---

## Keeping the connection alive

Firebase refresh tokens don't expire on a fixed schedule, but a long-unused one
is more likely to get flagged. Once deployed, hit `GET /api/profile`
periodically (a cron job or uptime monitor) to keep the token exercising a
refresh cycle. If it ever dies, open
`https://your-app.wasmer.app/login?token=YOUR_REAUTH_ACCESS_TOKEN`, sign in with
the same Google account, and it reconnects in a few seconds.

If Wasmer's runtime resets the filesystem between cold starts, the app falls
back to the `CLOUDGATE_REFRESH_TOKEN` you set on each start — so that value is
your durable source of truth. Set `CLOUDGATE_STATE_DIR` to a persistent volume
path if your plan provides one.

---

## Notes

- **CORS:** `/api/*` sends permissive CORS headers so standalone tools can call
  it — the `CREDENTIALS` gate is what actually protects it, so set it.
- **Persistent storage caveat:** `credentials.json` / `custom_categories.json`
  are written to disk; serverless filesystems may not persist across cold
  starts, in which case token auto-rotation and custom categories fall back to
  their bootstrap values each start (not broken, just less self-healing).
- **Deploy wasn't tested from where this was built** (no Wasmer CLI/account
  available) — if the auto-detected build misbehaves, check
  <https://docs.wasmer.io/edge> for current Node.js app requirements.
