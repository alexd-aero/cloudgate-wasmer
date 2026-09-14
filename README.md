# cloudgate-client (Node.js / Wasmer deployable)

Feature-identical Node.js/Express port of the Python/Flask CloudGate client
in [alexd-aero/cloudgate-client](https://github.com/alexd-aero/cloudgate-client)
(that repo is the working local/dev copy with the full history; this one is
a standalone copy of just the Node app, kept **Python-free on purpose** so
Wasmer's build auto-detection doesn't get confused and try to run it as a
Python/ASGI app).

Full endpoint docs: see `API_DOCS.md` in the other repo - same routes here.

## Run locally

```bash
npm install
CLOUDGATE_EMAIL=you@example.com CLOUDGATE_REFRESH_TOKEN=... node src/server.js
```

Or drop a `src/credentials.json` (`{"email": "...", "refresh_token": "..."}`)
and skip the env vars. Defaults to port `5058` (`PORT` env var to change it).

## Deploying to Wasmer Edge

Import **this repo** (not the monorepo one) in the Wasmer dashboard - since
there's no `requirements.txt`/`.py` file anywhere here, it should
auto-detect Node.js and use `npm install` / `npm start` without needing any
manual Build Settings overrides.

Set these in the app's environment variables (Settings > Environment
Variables), not committed anywhere in this repo:
- `CLOUDGATE_EMAIL`
- `CLOUDGATE_REFRESH_TOKEN`
- `REAUTH_ACCESS_TOKEN` - a random secret string (`openssl rand -base64 32`
  or similar). Gates `/login` - see below for why this exists and isn't
  optional for a public deployment.
- `CREDENTIALS` (recommended) - HTTP Basic Auth gate over the **whole** app,
  in the form `"user","pass"` (quotes included). When set, every request -
  including all `/api/*` routes, which otherwise have no auth and operate
  directly on the owner's storage (browse/upload/**download/delete**) -
  requires this username and password. Leave it unset only for local dev.
  Browsers prompt once and then send it automatically. Example value:
  `"alex","s0me-long-random-pass"`.

**I couldn't test an actual deploy** (no Wasmer CLI/account available where
this was built) - if the auto-detected build still misbehaves, check
https://docs.wasmer.io/edge for the current Node.js app requirements.

### Keeping the refresh token alive

Firebase refresh tokens don't expire on a fixed schedule, but a long-unused
one is more likely to get flagged/revoked. Once this is deployed and has a
live URL, set up something (a cron job, an uptime monitor, a scheduled
GitHub Action in the other repo) to hit `GET /api/profile` on it
periodically - that forces a token-refresh cycle. If the token does ever
die anyway, open `https://your-app.wasmer.app/login?token=YOUR_REAUTH_ACCESS_TOKEN`
for a fresh Google sign-in that reconnects in about 10 seconds - **save that
full URL somewhere private** (password manager, not a chat log or anywhere
public), it's the only way to reach the page.

### Why `/login` requires a token

A public, unauthenticated "Sign in with Google" page - even one whose
backend correctly rejects any account but the owner's - is
indistinguishable from an OAuth-phishing page to hosting providers'
automated abuse scanners (and to any stranger who stumbles on the link):
it invites a real Google consent screen before the app ever gets a chance
to check whose account it is. Gating the page behind
`REAUTH_ACCESS_TOKEN` means it 404s for everyone except someone who
already has the secret link. This app got disabled by Wasmer's Trust &
Safety team once already for exactly this pattern before the gate was
added - don't remove it without a different fix in place.

### Persistent storage caveat

`credentials.json` and `custom_categories.json` are written to disk so the
refresh token survives restarts and custom categories persist. **Serverless
platforms often don't guarantee a persistent, writable filesystem across
cold starts/instances.** If Wasmer's runtime resets the filesystem between
invocations:
- Refresh-token auto-rotation will silently stop sticking between
  invocations (falls back to the bootstrap env var each cold start - not
  broken, just less self-healing).
- Custom categories created via the API may not survive a cold start.

Set `CLOUDGATE_STATE_DIR` to a mounted/persistent volume path in `app.yaml`
if Wasmer provides one for your plan; otherwise a small external store
(KV service, or even just S3 itself) would be the more robust fix - ask if
you want that built out.

### CORS

Same-origin only right now (no CORS headers).
