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

**I couldn't test an actual deploy** (no Wasmer CLI/account available where
this was built) - if the auto-detected build still misbehaves, check
https://docs.wasmer.io/edge for the current Node.js app requirements.

### Keeping the refresh token alive

Firebase refresh tokens don't expire on a fixed schedule, but a long-unused
one is more likely to get flagged/revoked. Once this is deployed and has a
live URL, set up something (a cron job, an uptime monitor, a scheduled
GitHub Action in the other repo) to hit `GET /api/profile` on it
periodically - that forces a token-refresh cycle. If the token does ever
die anyway, `/login` on the deployed app does a fresh Google sign-in and
reconnects in about 10 seconds.

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
