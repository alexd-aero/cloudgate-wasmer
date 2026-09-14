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

1. **Get your own private copy of this repo** (fork it, or push these files to
   a new repo). If you're going to commit your credentials into `app.yaml`
   (below), the repo **must be private** — it will contain your secrets.
2. **Deploy to Wasmer** — dashboard → *Deploy → Import a Git repository* → pick
   your repo. Or `wasmer deploy` from the CLI. Node.js is auto-detected.
3. **Open `/setup` on your new URL** (`https://your-app.wasmer.app/setup`). That
   page walks you through capturing your CloudGate token and generating the
   env config to paste back into `app.yaml`, then redeploy.

That's it. Details below.

---

## The `/setup` page

Visit **`/setup`** on your deployment (or open `public/setup.html` locally). It
runs entirely in your browser and stores nothing on the server. It:

- **Captures your CloudGate refresh token.** It gives you a one-line console
  script (with a **Copy** button) to run in your CloudGate tab — it reads the
  session you're already signed into, refreshes it, prints your tokens, and
  copies the refresh token to your clipboard. (There's also a best-effort
  "Sign in with Google" button, but it only works if this app's domain is
  allow-listed in CloudGate's Firebase project, so the console script is the
  reliable path.)
- **Takes all your settings in one form** — email, refresh token, permanent
  access token (with a *Generate* button), and the username/password
  credentials — each with copy buttons.
- **Generates your config.** As you type, it builds the `app.yaml` `env:` block
  and a `.env` file, each with a **Copy** button. Paste the `app.yaml` block
  into your (private) repo, commit, and redeploy.

The same capture script also lives at
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
| `CREDENTIALS` | strongly recommended | `"user","pass"` | HTTP Basic Auth gate over the **whole** app |
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
requires this username and password. If it's unset or malformed, the app logs a
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
