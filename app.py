# Middleman: keeps NANGO_SECRET_KEY private and hands the browser a short-lived
# Connect session token so the Nango popup can run against local Docker.
import os
import requests
from flask import Flask, jsonify, request, send_file
from dotenv import load_dotenv

load_dotenv()  # reads NANGO_SECRET_KEY from .env

# Local Docker Nango (not cloud)
NANGO_URL = "http://localhost:3003"
INTEGRATION_ID = "github"
SECRET_KEY = os.environ["NANGO_SECRET_KEY"]

app = Flask(__name__)


def nango_headers():
    return {"Authorization": f"Bearer {SECRET_KEY}"}


@app.route("/")
def home():
    return send_file("index.html")


@app.post("/api/session")
def create_session():
    """Create a short-lived Connect session token for the browser popup."""
    body = {
        "end_user": {"id": "achsah-demo"},
        "allowed_integrations": [INTEGRATION_ID],
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
        # Common local-Docker cause: NANGO_ENCRYPTION_KEY unset on nango-server
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

    headers = {
        **nango_headers(),
        "Connection-Id": connection_id,
        "Provider-Config-Key": INTEGRATION_ID,
    }
    # Nango proxy: strips /proxy, attaches the stored GitHub token, calls GitHub
    resp = requests.get(
        f"{NANGO_URL}/proxy/user/repos",
        headers=headers,
        params={"per_page": 5, "sort": "updated"},
    )
    resp.raise_for_status()
    repos = [
        {"name": r["full_name"], "stars": r["stargazers_count"], "url": r["html_url"]}
        for r in resp.json()
    ]
    return jsonify(repos)


if __name__ == "__main__":
    # Port 5002 so it doesn't clash with other local apps
    app.run(port=5002, debug=True)
