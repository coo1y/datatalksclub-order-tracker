#!/usr/bin/env python3
"""Incident responder: receives Grafana alert webhooks, gathers the context an
on-call engineer would need (affected endpoint, recent logs, recent traces),
saves it, then runs Claude Code in headless mode to investigate.

Usage:
    python3 incident-response/service.py

No third-party dependencies are required; only the standard library plus the
`claude` CLI on PATH.
"""

import json
import logging
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(os.getenv("RESPONDER_PORT", "8001"))
LOKI_URL = os.getenv("LOKI_URL", "http://localhost:3100")
TEMPO_URL = os.getenv("TEMPO_URL", "http://localhost:3200")
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
GRAFANA_URL = os.getenv("GRAFANA_URL", "http://localhost:3000")
LOOKBACK_MINUTES = int(os.getenv("RESPONDER_LOOKBACK_MINUTES", "15"))
CLAUDE_TIMEOUT_SECONDS = int(os.getenv("RESPONDER_CLAUDE_TIMEOUT", "600"))

REPO_ROOT = Path(__file__).resolve().parent.parent
INCIDENTS_DIR = Path(__file__).resolve().parent / "incidents"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("incident-response")


def http_get_json(url: str, params: dict) -> dict:
    query = urllib.parse.urlencode(params)
    with urllib.request.urlopen(f"{url}?{query}", timeout=10) as resp:
        return json.loads(resp.read())


def fetch_logs(minutes: int) -> dict:
    now_ns = time.time_ns()
    start_ns = now_ns - minutes * 60 * 1_000_000_000
    try:
        return http_get_json(
            f"{LOKI_URL}/loki/api/v1/query_range",
            {
                "query": '{service_name="order-tracker"}',
                "start": start_ns,
                "end": now_ns,
                "limit": 200,
            },
        )
    except Exception as exc:  # noqa: BLE001 - best-effort context gathering
        logger.warning("failed to fetch logs from Loki: %s", exc)
        return {"error": str(exc)}


def fetch_traces(minutes: int) -> dict:
    now_s = int(time.time())
    start_s = now_s - minutes * 60
    try:
        return http_get_json(
            f"{TEMPO_URL}/api/search",
            {
                "tags": "service.name=order-tracker",
                "start": start_s,
                "end": now_s,
                "limit": 20,
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("failed to fetch traces from Tempo: %s", exc)
        return {"error": str(exc)}


def fetch_metrics(minutes: int) -> dict:
    try:
        return http_get_json(
            f"{PROMETHEUS_URL}/api/v1/query",
            {"query": f"sum by (http_route, http_status_code) (increase(http_server_requests_total[{minutes}m]))"},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("failed to fetch metrics from Prometheus: %s", exc)
        return {"error": str(exc)}


def slugify(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-")
    return value or "alert"


def build_incident_id(payload: dict) -> str:
    alerts = payload.get("alerts") or [{}]
    alertname = alerts[0].get("labels", {}).get("alertname", "alert")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{slugify(alertname)}"


def affected_endpoints(payload: dict) -> list[str]:
    routes = []
    for alert in payload.get("alerts", []):
        route = alert.get("labels", {}).get("http_route")
        if route and route not in routes:
            routes.append(route)
    return routes


def build_prompt(incident_dir: Path, payload: dict) -> str:
    alerts = payload.get("alerts", [])
    routes = affected_endpoints(payload)
    summary_lines = []
    for alert in alerts:
        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})
        summary_lines.append(
            f"- alertname={labels.get('alertname', 'unknown')} status={alert.get('status', 'unknown')} "
            f"labels={labels} summary={annotations.get('summary', '')} "
            f"description={annotations.get('description', '')}"
        )
    alerts_block = "\n".join(summary_lines) or "(no alerts in payload)"
    routes_block = ", ".join(routes) if routes else "(none specified in the alert labels)"

    rel = incident_dir.relative_to(REPO_ROOT)
    return f"""You are the on-call incident responder for the order-tracker service.
A Grafana alert just fired and was sent to the incident-response webhook. Investigate it
using the saved context below.

1. Decide whether this is a real incident or a test/non-issue (e.g. a "test" label,
   or an alertname like "ResponderTest"). If it is a test/non-issue, do not modify any
   files - just confirm nothing is wrong and stop.

2. If it is a real incident: find the root cause. Use the saved logs and traces to find
   the failing request and any error/traceback, then read the relevant application code
   under app/ to confirm the bug.

3. You have write access to this repository - use it. Once you have identified the root
   cause with high confidence (e.g. you can point to the exact line and explain precisely
   why it fails), apply the minimal fix yourself using your file-editing tools before you
   finish responding. Do not just describe the fix or recommend it - make the edit. Keep
   the fix scoped to the actual bug; do not refactor unrelated code. Do NOT restart,
   rebuild, or redeploy the app yourself; a human will do that after reviewing your change.
   Only skip the edit and escalate to a developer instead if you are genuinely uncertain
   of the root cause or the fix would be large/risky - being able to state the fix clearly
   is not a reason to skip applying it.

4. Report back: what was broken, the affected endpoint(s), the root cause, and either a
   summary of the fix you applied (file + change) or why you escalated instead.

Affected endpoint(s) from alert labels: {routes_block}

Alerts received:
{alerts_block}

Saved incident context is in {rel}/:
- alert.json    - the raw webhook payload
- metrics.json  - recent Prometheus request counts by route and status code
- logs.json     - recent Loki logs for the order-tracker service
- traces.json   - recent Tempo traces for the order-tracker service

Keep your final answer under 200 words, and end it with a one-line verdict starting
with "Verdict:".
"""


def run_claude_headless(prompt: str) -> str:
    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--dangerously-skip-permissions"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=CLAUDE_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return "ERROR: `claude` CLI not found on PATH. Install Claude Code to enable the responder."
    except subprocess.TimeoutExpired:
        return f"ERROR: claude did not finish within {CLAUDE_TIMEOUT_SECONDS}s."

    if result.returncode != 0:
        return f"ERROR: claude exited with code {result.returncode}.\nstderr:\n{result.stderr.strip()}"
    return result.stdout.strip()


def handle_alert(payload: dict) -> dict:
    incident_id = build_incident_id(payload)
    incident_dir = INCIDENTS_DIR / incident_id
    incident_dir.mkdir(parents=True, exist_ok=True)

    logger.info("incident %s: gathering context", incident_id)
    (incident_dir / "alert.json").write_text(json.dumps(payload, indent=2))
    (incident_dir / "metrics.json").write_text(json.dumps(fetch_metrics(LOOKBACK_MINUTES), indent=2))
    (incident_dir / "logs.json").write_text(json.dumps(fetch_logs(LOOKBACK_MINUTES), indent=2))
    (incident_dir / "traces.json").write_text(json.dumps(fetch_traces(LOOKBACK_MINUTES), indent=2))

    prompt = build_prompt(incident_dir, payload)
    (incident_dir / "prompt.txt").write_text(prompt)

    logger.info("incident %s: starting claude in headless mode", incident_id)
    started = time.monotonic()
    response = run_claude_headless(prompt)
    elapsed = time.monotonic() - started
    logger.info("incident %s: claude finished in %.1fs", incident_id, elapsed)

    (incident_dir / "response.txt").write_text(response)

    return {
        "incident_id": incident_id,
        "alerts_received": len(payload.get("alerts", [])),
        "affected_endpoints": affected_endpoints(payload),
        "elapsed_seconds": round(elapsed, 1),
        "response": response,
    }


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802 - stdlib naming convention
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path != "/alerts":
            self._send_json(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError as exc:
            self._send_json(400, {"error": f"invalid JSON: {exc}"})
            return

        try:
            result = handle_alert(payload)
        except Exception as exc:  # noqa: BLE001
            logger.exception("failed to handle alert")
            self._send_json(500, {"error": str(exc)})
            return

        self._send_json(200, result)

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        logger.info("%s - %s", self.address_string(), format % args)


def main():
    INCIDENTS_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    logger.info("incident responder listening on :%s (POST /alerts)", PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
