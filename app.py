# Middleman: keeps NANGO_SECRET_KEY private and hands the browser a short-lived
# Connect session token so the Nango popup can run against local Docker.
# Okta "Add user" requests are gated by Slack Workspace Admin Approve/Deny.
import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_file

load_dotenv()

NANGO_URL = os.getenv("NANGO_URL", "http://localhost:3003")
ALLOWED_INTEGRATIONS = {"github", "okta", "slack"}
SECRET_KEY = os.environ["NANGO_SECRET_KEY"]
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "")
SLACK_APPROVAL_CHANNEL = os.getenv("SLACK_APPROVAL_CHANNEL", "")
NGROK_DOMAIN = os.getenv("NGROK_DOMAIN", "").strip().lower()
PROCESSING_TIMEOUT_SEC = 120

app = Flask(__name__)

_requests_lock = threading.Lock()
# request_id -> pending approval record (in-memory; wiped on restart)
USER_REQUESTS: dict[str, dict] = {}


def nango_headers():
    return {"Authorization": f"Bearer {SECRET_KEY}"}


def nango_proxy_headers(connection_id: str, provider: str) -> dict:
    return {
        **nango_headers(),
        "Connection-Id": connection_id,
        "Provider-Config-Key": provider,
    }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def via_ngrok() -> bool:
    """True when the request Host looks like the public ngrok tunnel."""
    host = (request.host or "").split(":")[0].lower()
    if "ngrok" in host:
        return True
    if NGROK_DOMAIN and (host == NGROK_DOMAIN or host.endswith("." + NGROK_DOMAIN)):
        return True
    return False


@app.before_request
def restrict_ngrok_surface():
    # Browser uses localhost:5002; Slack interactivity uses ngrok.
    # Only expose the signed Slack callback on the public tunnel.
    if not via_ngrok():
        return None
    if request.method == "POST" and request.path == "/api/slack/interactions":
        return None
    return jsonify(error="Forbidden via ngrok — use localhost for the UI"), 403


def slack_api_ok(resp: requests.Response) -> tuple[bool, dict, str]:
    """Slack returns HTTP 200 with ok:false on many failures."""
    try:
        body = resp.json()
    except ValueError:
        return False, {}, resp.text or f"HTTP {resp.status_code}"
    if not resp.ok:
        return False, body, body.get("error") or resp.text
    if not body.get("ok"):
        return False, body, body.get("error") or "slack_ok_false"
    return True, body, ""


def verify_slack_signature(raw_body: bytes, timestamp: str, signature: str) -> bool:
    if not SLACK_SIGNING_SECRET or not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs(time.time() - ts) > 60 * 5:
        return False
    basestring = b"v0:" + timestamp.encode("utf-8") + b":" + raw_body
    digest = (
        "v0="
        + hmac.new(
            SLACK_SIGNING_SECRET.encode("utf-8"),
            basestring,
            hashlib.sha256,
        ).hexdigest()
    )
    return hmac.compare_digest(digest, signature)


def okta_error_summary(resp: requests.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text or f"HTTP {resp.status_code}"
    causes = body.get("errorCauses") or []
    if causes and isinstance(causes, list):
        summary = causes[0].get("errorSummary")
        if summary:
            return summary
    return body.get("errorSummary") or body.get("errorCode") or resp.text


def public_request_view(rec: dict) -> dict:
    status = rec["status"]
    error = rec.get("error")
    if status == "processing":
        started = rec.get("processing_started_at")
        if started:
            try:
                started_dt = datetime.fromisoformat(started)
                if datetime.now(timezone.utc) - started_dt > timedelta(
                    seconds=PROCESSING_TIMEOUT_SEC
                ):
                    status = "failed"
                    error = error or "timed out — please resubmit"
            except ValueError:
                pass
    return {
        "request_id": rec["request_id"],
        "firstName": rec["firstName"],
        "lastName": rec["lastName"],
        "email": rec["email"],
        "status": status,
        "error": error,
        "decided_by": rec.get("decided_by"),
        "created_at": rec.get("created_at"),
    }


def post_response_url(response_url: str, text: str, ephemeral: bool = True) -> None:
    if not response_url:
        return
    payload = {"text": text}
    if ephemeral:
        payload["response_type"] = "ephemeral"
        payload["replace_original"] = False
    try:
        requests.post(response_url, json=payload, timeout=10)
    except requests.RequestException:
        pass


def slack_chat_update(slack_connection_id: str, channel: str, ts: str, text: str) -> tuple[bool, str]:
    try:
        resp = requests.post(
            f"{NANGO_URL}/proxy/chat.update",
            headers=nango_proxy_headers(slack_connection_id, "slack"),
            json={
                "channel": channel,
                "ts": ts,
                "text": text,
                "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
            },
            timeout=30,
        )
    except requests.RequestException as exc:
        return False, str(exc)
    ok, _, err = slack_api_ok(resp)
    return ok, err


def slack_users_is_admin(slack_connection_id: str, user_id: str) -> tuple[bool | None, str]:
    """Returns (is_admin, error). is_admin is None when the lookup failed."""
    try:
        resp = requests.get(
            f"{NANGO_URL}/proxy/users.info",
            headers=nango_proxy_headers(slack_connection_id, "slack"),
            params={"user": user_id},
            timeout=30,
        )
    except requests.RequestException as exc:
        return None, str(exc)
    ok, body, err = slack_api_ok(resp)
    if not ok:
        return None, err
    user = body.get("user") or {}
    return bool(user.get("is_admin") or user.get("is_owner")), ""


def process_admin_decision(request_id: str, action_id: str, admin_user_id: str) -> None:
    with _requests_lock:
        rec = USER_REQUESTS.get(request_id)
        if not rec or rec["status"] != "processing":
            return
        # shallow copy fields we need outside the lock
        snapshot = dict(rec)

    outcome_text = ""
    final_status = "failed"
    error = None

    if action_id == "okta_deny":
        final_status = "denied"
        outcome_text = (
            f"*Denied* by <@{admin_user_id}> — "
            f"{snapshot['firstName']} {snapshot['lastName']} ({snapshot['email']})"
        )
    elif action_id == "okta_approve":
        try:
            resp = requests.post(
                f"{NANGO_URL}/proxy/api/v1/users",
                headers=nango_proxy_headers(snapshot["okta_connection_id"], "okta"),
                params={"activate": "false"},
                json={
                    "profile": {
                        "firstName": snapshot["firstName"],
                        "lastName": snapshot["lastName"],
                        "email": snapshot["email"],
                        "login": snapshot["email"],
                    }
                },
                timeout=30,
            )
        except requests.RequestException as exc:
            final_status = "failed"
            error = str(exc)
            outcome_text = (
                f"*Failed* (approved by <@{admin_user_id}> but Okta error): {error}"
            )
        else:
            if resp.ok:
                final_status = "approved"
                outcome_text = (
                    f"*Approved* by <@{admin_user_id}> — created Okta user "
                    f"{snapshot['email']} (STAGED; provisioned, not signed in yet)."
                )
            else:
                final_status = "failed"
                error = okta_error_summary(resp)
                outcome_text = (
                    f"*Failed* (approved by <@{admin_user_id}> but Okta error): {error}"
                )
    else:
        final_status = "failed"
        error = f"Unknown action {action_id}"
        outcome_text = f"*Failed*: {error}"

    update_ok, update_err = slack_chat_update(
        snapshot["slack_connection_id"],
        snapshot.get("slack_channel") or SLACK_APPROVAL_CHANNEL,
        snapshot.get("slack_ts") or "",
        outcome_text,
    )
    if not update_ok:
        error = (error + "; " if error else "") + f"chat.update failed: {update_err}"

    with _requests_lock:
        rec = USER_REQUESTS.get(request_id)
        if not rec:
            return
        rec["status"] = final_status
        rec["decided_by"] = admin_user_id
        rec["error"] = error
        rec["updated_at"] = utc_now_iso()


@app.route("/")
def home():
    return send_file("index.html")


@app.post("/api/session")
def create_session():
    """Create a short-lived Connect session token for the browser popup."""
    payload = request.get_json(silent=True) or {}
    integration = payload.get("integration", "github")
    if integration not in ALLOWED_INTEGRATIONS:
        return jsonify(error=f"integration must be one of {sorted(ALLOWED_INTEGRATIONS)}"), 400

    body = {
        "end_user": {"id": "achsah-demo"},
        "allowed_integrations": [integration],
    }
    try:
        resp = requests.post(
            f"{NANGO_URL}/connect/sessions",
            json=body,
            headers=nango_headers(),
            timeout=15,
        )
    except requests.RequestException as exc:
        return jsonify(error=f"Could not reach local Nango at {NANGO_URL}: {exc}"), 502

    if not resp.ok:
        detail = resp.text
        return (
            jsonify(
                error="Nango failed to create connect session",
                detail=detail,
                hint=(
                    "On your Nango Docker host, set NANGO_ENCRYPTION_KEY "
                    "(openssl rand -base64 32) in the .env used by docker-compose, "
                    "then restart nango-server. Connect sessions need that key."
                ),
            ),
            502,
        )

    return jsonify(token=resp.json()["data"]["token"])


@app.get("/api/repos")
def get_repos():
    """Proxy GitHub /user/repos through Nango using the connection from Connect UI."""
    connection_id = request.args.get("connection_id")
    if not connection_id:
        return jsonify(error="connection_id is required — connect GitHub first"), 400

    headers = nango_proxy_headers(connection_id, "github")
    try:
        resp = requests.get(
            f"{NANGO_URL}/proxy/user/repos",
            headers=headers,
            params={"per_page": 5, "sort": "updated"},
            timeout=30,
        )
    except requests.RequestException as exc:
        return jsonify(error=f"Could not reach local Nango at {NANGO_URL}: {exc}"), 502

    if not resp.ok:
        return jsonify(error="Failed to load GitHub repos", detail=resp.text), 502

    repos = [
        {"name": r["full_name"], "stars": r["stargazers_count"], "url": r["html_url"]}
        for r in resp.json()
    ]
    return jsonify(repos)


@app.get("/api/okta/users")
def get_okta_users():
    """Proxy Okta /api/v1/users through Nango using the connection from Connect UI."""
    connection_id = request.args.get("connection_id")
    if not connection_id:
        return jsonify(error="connection_id is required — connect Okta first"), 400

    headers = nango_proxy_headers(connection_id, "okta")
    try:
        resp = requests.get(
            f"{NANGO_URL}/proxy/api/v1/users",
            headers=headers,
            timeout=30,
        )
    except requests.RequestException as exc:
        return jsonify(error=f"Could not reach local Nango at {NANGO_URL}: {exc}"), 502

    if not resp.ok:
        return jsonify(error="Failed to load Okta users", detail=resp.text), 502

    users = []
    for u in resp.json():
        profile = u.get("profile") or {}
        users.append(
            {
                "firstName": profile.get("firstName"),
                "lastName": profile.get("lastName"),
                "email": profile.get("email"),
                "status": u.get("status"),
            }
        )
    return jsonify(users)


@app.post("/api/okta/user-requests")
def create_user_request():
    """Queue an Okta user create behind Slack Workspace Admin Approve/Deny."""
    if not SLACK_APPROVAL_CHANNEL:
        return jsonify(error="SLACK_APPROVAL_CHANNEL is not set in .env"), 500
    if not SLACK_SIGNING_SECRET:
        return jsonify(error="SLACK_SIGNING_SECRET is not set in .env"), 500

    payload = request.get_json(silent=True) or {}
    first = (payload.get("firstName") or "").strip()
    last = (payload.get("lastName") or "").strip()
    email = (payload.get("email") or "").strip()
    okta_connection_id = (payload.get("okta_connection_id") or "").strip()
    slack_connection_id = (payload.get("slack_connection_id") or "").strip()

    if not first or not last or not email:
        return jsonify(error="firstName, lastName, and email are required"), 400
    if "@" not in email:
        return jsonify(error="email must look like an email address (used as Okta login)"), 400
    if not okta_connection_id:
        return jsonify(error="okta_connection_id is required — connect Okta first"), 400
    if not slack_connection_id:
        return jsonify(error="slack_connection_id is required — connect Slack first"), 400

    request_id = uuid.uuid4().hex
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "Okta user approval"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*First name:*\n{first}"},
                {"type": "mrkdwn", "text": f"*Last name:*\n{last}"},
                {"type": "mrkdwn", "text": f"*Email / login:*\n{email}"},
                {"type": "mrkdwn", "text": f"*Request:*\n`{request_id}`"},
            ],
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": "okta_approve",
                    "value": request_id,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "style": "danger",
                    "action_id": "okta_deny",
                    "value": request_id,
                },
            ],
        },
    ]

    try:
        resp = requests.post(
            f"{NANGO_URL}/proxy/chat.postMessage",
            headers=nango_proxy_headers(slack_connection_id, "slack"),
            json={
                "channel": SLACK_APPROVAL_CHANNEL,
                "text": f"Approve Okta user {email}?",
                "blocks": blocks,
            },
            timeout=30,
        )
    except requests.RequestException as exc:
        return jsonify(error=f"Could not reach Nango/Slack: {exc}"), 502

    ok, body, err = slack_api_ok(resp)
    if not ok:
        return (
            jsonify(
                error="Slack chat.postMessage failed",
                detail=err,
                hint="Invite the bot to #approvals and confirm SLACK_APPROVAL_CHANNEL is the C… id.",
            ),
            502,
        )

    rec = {
        "request_id": request_id,
        "firstName": first,
        "lastName": last,
        "email": email,
        "okta_connection_id": okta_connection_id,
        "slack_connection_id": slack_connection_id,
        "status": "pending",
        "slack_channel": body.get("channel") or SLACK_APPROVAL_CHANNEL,
        "slack_ts": (body.get("message") or {}).get("ts") or body.get("ts"),
        "decided_by": None,
        "error": None,
        "processing_started_at": None,
        "created_at": utc_now_iso(),
    }
    with _requests_lock:
        USER_REQUESTS[request_id] = rec

    return jsonify(request_id=request_id, status="pending")


@app.get("/api/okta/user-requests")
def list_user_requests():
    with _requests_lock:
        items = [public_request_view(r) for r in USER_REQUESTS.values()]
    items.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    return jsonify(items)


@app.post("/api/slack/interactions")
def slack_interactions():
    # Must use the exact bytes Slack signed — do not re-serialize JSON.
    raw_body = request.get_data(cache=False, as_text=False)
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")
    if not verify_slack_signature(raw_body, timestamp, signature):
        return jsonify(error="invalid Slack signature"), 401

    form = raw_body.decode("utf-8")
    # application/x-www-form-urlencoded: payload=<json>
    parsed = parse_qs(form)
    payload_raw = (parsed.get("payload") or [None])[0]
    if not payload_raw:
        return jsonify(error="missing payload"), 400
    payload = json.loads(payload_raw)

    if payload.get("type") != "block_actions":
        return "", 200

    actions = payload.get("actions") or []
    if not actions:
        return "", 200
    action = actions[0]
    action_id = action.get("action_id")
    request_id = action.get("value")
    user_id = (payload.get("user") or {}).get("id")
    response_url = payload.get("response_url") or ""

    with _requests_lock:
        rec = USER_REQUESTS.get(request_id) if request_id else None
        rec_snapshot = dict(rec) if rec else None

    if not rec_snapshot:
        post_response_url(
            response_url,
            "Request expired, please resubmit.",
            ephemeral=True,
        )
        # Best-effort: if the original message is still there, replace buttons.
        # Without a stored slack_connection_id we can only use response_url.
        if response_url:
            try:
                requests.post(
                    response_url,
                    json={
                        "replace_original": True,
                        "text": "Request expired, please resubmit.",
                    },
                    timeout=10,
                )
            except requests.RequestException:
                pass
        return "", 200

    is_admin, admin_err = slack_users_is_admin(
        rec_snapshot["slack_connection_id"], user_id
    )
    if is_admin is None:
        post_response_url(
            response_url,
            f"Could not verify admin status ({admin_err}). Try again.",
            ephemeral=True,
        )
        return "", 200

    if not is_admin:
        # Do not lock or mutate the request — a real admin can still approve.
        post_response_url(
            response_url,
            "Only Workspace Admins can approve or deny Okta user requests.",
            ephemeral=True,
        )
        return "", 200

    claimed = False
    with _requests_lock:
        rec = USER_REQUESTS.get(request_id)
        if rec and rec["status"] == "pending":
            rec["status"] = "processing"
            rec["processing_started_at"] = utc_now_iso()
            rec["decided_by"] = user_id
            claimed = True

    if not claimed:
        post_response_url(
            response_url,
            "This request is already being handled or was already decided.",
            ephemeral=True,
        )
        return "", 200

    threading.Thread(
        target=process_admin_decision,
        args=(request_id, action_id, user_id),
        daemon=True,
    ).start()
    return "", 200


if __name__ == "__main__":
    # Port 5002 so it doesn't clash with other local apps.
    # Never leave FLASK_DEBUG=1 on for demos / Docker (exposes debugger on 0.0.0.0).
    app.run(
        host="0.0.0.0",
        port=5002,
        debug=os.getenv("FLASK_DEBUG") == "1",
    )
