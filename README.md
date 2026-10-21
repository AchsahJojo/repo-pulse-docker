# Nango Demos (Repo Pulse)

Flask demos against a **local** Nango instance: GitHub repos, Okta user list, and **Slack-approved Okta user creation**.

## Run with Docker

Start Nango if it is not already running:

```bash
cd ~/nango && docker compose up -d
```

Start the app:

```bash
cd ~/code/repo-pulse-docker && docker compose up -d --build
```

Open [http://localhost:5002/](http://localhost:5002/) in your browser (always use localhost for the UI).

## Stop

```bash
docker compose down
```

## Environment (`.env`, never commit)

| Variable | Purpose |
|---|---|
| `NANGO_SECRET_KEY` | Nango secret (required) |
| `SLACK_SIGNING_SECRET` | Slack app signing secret (verify interactivity) |
| `SLACK_APPROVAL_CHANNEL` | Channel **ID** `C…` (not `#approvals`) |
| `NGROK_DOMAIN` | Optional; static ngrok host (e.g. `abc.ngrok-free.app`) for the Host check |
| `FLASK_DEBUG` | Set to `1` only while coding — leave unset for demos/Docker |
| `NANGO_URL` | Set automatically in Docker to `http://host.docker.internal:3003` |

## Slack + Nango setup (once)

1. Slack app with bot scopes `chat:write` and `users:read`.
2. OAuth redirect for Nango: try `http://localhost:3003/oauth/callback` first.
3. In Nango, create integration id **`slack`** with that app’s Client ID/Secret.
4. Private `#approvals` channel; invite the bot; copy Channel ID into `.env`.
5. Promote demo approvers to **Workspace Admins** (throwaway demo workspace only).
6. Keep existing **`okta`** (and optional `github`) integrations.

## Concerns & recovery (read before demos)

### Two public URLs — only one is fixed

| URL purpose | Points at | How we stabilize |
|---|---|---|
| Slack **Interactivity** Request URL | Flask `:5002` → `/api/slack/interactions` | Claim ngrok’s **free static domain** and run `ngrok http --url=YOUR-DOMAIN 5002`. Set the Slack Request URL to `https://YOUR-DOMAIN/api/slack/interactions` **once**. |
| Slack **OAuth** redirect for Nango Connect | Nango `:3003` → `/oauth/callback` | Try `http://localhost:3003/oauth/callback` first. If Slack rejects non-HTTPS, use a **second** ngrok tunnel to `:3003` for the one-time Connect — not for Approve/Deny. |

**Important:** the static ngrok domain fixes **only** the Flask/interactivity URL. The Nango OAuth callback can still change (or stay on localhost). Do not assume both URLs are permanent.

### Ngrok does not expose the whole UI

If the request `Host` looks like ngrok, the app allows **only** `POST /api/slack/interactions` and returns **403** for everything else. Use `localhost:5002` in the browser. Still: don’t leave the tunnel up longer than needed.

### Preflight checklist (~10 minutes before presenting)

1. Nango is up; app is up; `FLASK_DEBUG` is off.
2. Static ngrok is running; Slack Interactivity URL matches.
3. Okta and Slack are connected in the UI (or reconnect).
4. Bot is in `#approvals`; `SLACK_APPROVAL_CHANNEL` is the `C…` id.
5. Approvers are Workspace Admins.
6. Optional spike: submit a request and confirm a Slack message appears (`ok: true` — Slack can return HTTP 200 with `"ok": false`).

### Demo behavior to remember

- **Approved means provisioned, not signed in** — Okta users are created with `activate=false` (status **STAGED**).
- Non-admin button clicks get a private “admins only” message; the request stays **pending** so a real admin can still approve.
- Do **not** restart the app between submit and approve (in-memory store). If you do, Slack should say **Request expired, please resubmit**.
- Stuck `processing` longer than 2 minutes is shown as failed — submit a new request.
- If `chat.update` fails, the web **User requests** list is the source of truth for errors (including Okta `errorCauses[0].errorSummary`).
- Duplicate Okta login → failed with Okta’s summary; submit a new request (no retry of the same id).
- Stale Nango connections (401/404) clear `localStorage` and show Connect again.

### Backup

Record a short video of a full successful run in case the live demo fails.

## Notes

- `.env` is loaded by Compose and is not copied into the image (see `.dockerignore`).
- Do not also run `python3 app.py` on port `5002` while the container is up.
- After code changes: `docker compose up -d --build`.
