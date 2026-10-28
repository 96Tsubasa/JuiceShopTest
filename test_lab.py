#!/usr/bin/env python3
"""Exercise the real local Juice Shop/CRS lab using only Python's standard library."""

import argparse
import base64
import binascii
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler, Request


DIRECT = "http://localhost:3000"
PROTECTED = "http://localhost:8080"
PAYLOAD = {"email": "' OR 1=1--", "password": "test"}
PROJECT = Path(__file__).resolve().parent


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Local requests must not use a machine-wide HTTP proxy or follow redirects.
HTTP = build_opener(ProxyHandler({}), NoRedirect())


def request(base, path="/", payload=None, marker=None):
    headers = {"Accept": "application/json, text/html", "User-Agent": "JuiceShop-WAF-Lab/1.0"}
    if marker:
        headers["X-Lab-Test"] = marker
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(base + path, data=body, headers=headers)
    try:
        with HTTP.open(req, timeout=10) as response:
            return response.status, response.read(), None
    except HTTPError as error:
        with error:
            return error.code, error.read(), None
    except (URLError, OSError, TimeoutError) as error:
        return None, b"", str(error)


def identity(body):
    """Inspect the app-issued token for the lab assertion; no signature validation."""
    try:
        response = json.loads(body)
        auth = response["authentication"]
        token = auth["token"]
        if not isinstance(token, str) or not token:
            return None, None
        encoded = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        user = claims["data"]
        if auth["umail"] != user["email"]:
            return None, None
        return user["email"], user["role"]
    except (ValueError, KeyError, IndexError, TypeError, AttributeError, binascii.Error):
        return None, None


def wait_ready(seconds):
    deadline = time.monotonic() + seconds
    pending = {DIRECT, PROTECTED}
    while pending:
        for base in tuple(pending):
            status, body, _ = request(base)
            if status == 200 and b"Juice Shop" in body:
                pending.remove(base)
        if not pending or time.monotonic() >= deadline:
            return
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def check_waf_log(marker, since):
    """Require SQLi detection + phase-2 denial for THIS request, not an old 403."""
    command = ["docker", "compose", "logs", "--no-color", "--no-log-prefix", "--since", since, "waf"]
    for attempt in range(5):
        try:
            logs = subprocess.run(
                command, cwd=PROJECT, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return False, "Cannot read Docker logs: " + str(error), {}
        if logs.returncode:
            return False, "docker compose logs failed: " + logs.stderr.strip(), {}
        for line in logs.stdout.splitlines():
            if marker not in line:
                continue
            try:
                transaction = json.loads(line)["transaction"]
                req = transaction["request"]
                headers = {key.lower(): value for key, value in req.get("headers", {}).items()}
                if headers.get("x-lab-test") != marker:
                    continue
                if req.get("method") != "POST" or req.get("uri", "").split("?")[0] != "/rest/user/login":
                    continue
                messages = transaction.get("messages", [])
                rule_ids = sorted({str(msg.get("details", {}).get("ruleId", "")) for msg in messages})
                sql_ids = [rule for rule in rule_ids if rule.startswith("942")]
                blocking_rule = any(
                    str(msg.get("details", {}).get("ruleId")) == "949110"
                    for msg in messages
                )
                transaction_id = str(transaction.get("unique_id", ""))
                # JSON audit details.match omits the phase. Correlate the error
                # log by ModSecurity's transaction ID, not just the endpoint.
                denial = blocking_rule and bool(transaction_id) and any(
                    f'[unique_id "{transaction_id}"]' in entry
                    and '[id "949110"]' in entry
                    and "Access denied with code 403 (phase 2)" in entry
                    for entry in logs.stdout.splitlines()
                )
                engine = transaction.get("producer", {}).get("secrules_engine", "")
                status = transaction.get("response", {}).get("http_code")
                interrupted = transaction.get("is_interrupted") is True
                passed = bool(sql_ids) and denial and interrupted and status == 403 and engine.lower() in {"enabled", "on"}
                evidence = {
                    "request_marker": marker,
                    "transaction_id": transaction_id,
                    "rule_ids": rule_ids,
                    "sql_rule_ids": sql_ids,
                    "phase_2_denial": denial,
                    "rule_engine": engine,
                    "interrupted": interrupted,
                    "http_status": status,
                    "messages": [msg.get("message", "") for msg in messages],
                    "detection_data": [msg.get("details", {}).get("data", "") for msg in messages if str(msg.get("details", {}).get("ruleId", "")).startswith("942")],
                    "components": transaction.get("producer", {}),
                }
                detail = f"CRS rules={','.join(rule_ids)}; phase-2 denial={denial}; engine={engine}"
                return passed, detail, evidence
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
        if attempt < 4:
            time.sleep(1)
    return False, "No matching JSON audit event. Check WAF logging and Docker access.", {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait", type=int, default=90, metavar="SECONDS", help="wait for real apps (default: 90)")
    parser.add_argument("--email", default="admin@juice-sh.op", help="expected lab administrator email")
    parser.add_argument("--password", default="admin123", help="explicit password override for a customized lab")
    parser.add_argument("--skip-logs", action="store_true", help="HTTP checks only; Test 4 remains unverified")
    parser.add_argument("--output", type=Path, help="write results as JSON (without auth tokens or passwords)")
    args = parser.parse_args()
    if args.wait < 0:
        parser.error("--wait must be nonnegative")

    run_id = uuid.uuid4().hex
    since = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    results = []
    log_evidence = {}

    def record(name, passed, status, detail):
        results.append({"test": name, "passed": passed, "http_status": status, "detail": detail})
        print(f"[{'PASS' if passed else 'FAIL'}] {name}: HTTP {status if status is not None else 'N/A'}; {detail}")

    print("Real local lab: localhost:3000 (direct), localhost:8080 (WAF)")
    print("SQLi email: " + PAYLOAD["email"] + "; password: test")
    print("Run ID: " + run_id)
    print(f"Waiting up to {args.wait}s for Juice Shop...")
    wait_ready(args.wait)

    for label, base in (("UI direct", DIRECT), ("UI via WAF", PROTECTED)):
        status, body, error = request(base)
        passed = status == 200 and b"Juice Shop" in body
        record(label, passed, status, error or ("Juice Shop HTML received" if passed else "Missing Juice Shop HTML"))

    for label, base in (("Test 1 - SQLi direct", DIRECT), ("Test 2 - SQLi via WAF", PROTECTED)):
        marker = run_id + ("-waf" if base == PROTECTED else "-direct")
        status, body, error = request(base, "/rest/user/login", PAYLOAD, marker)
        email, role = identity(body)
        if base == DIRECT:
            passed = status == 200 and email == args.email and role == "admin"
            detail = f"authenticated email={email}, role={role}"
        else:
            passed = status == 403 and email is None
            detail = "403 observed; CRS attribution checked in Test 4"
        record(label, passed, status, error or detail)

    valid = {"email": args.email, "password": args.password}
    for label, base in (("Credential baseline direct", DIRECT), ("Test 3 - valid login via WAF", PROTECTED)):
        status, body, error = request(base, "/rest/user/login", valid)
        email, role = identity(body)
        passed = status == 200 and email == args.email and role == "admin"
        detail = f"authenticated email={email}, role={role}"
        if not passed and status == 401:
            detail += "; credentials rejected by app; inspect the actual Juice Shop version/config"
        record(label, passed, status, error or detail)

    invalid = {"email": args.email, "password": "wrong-password-" + run_id}
    for label, base in (("Invalid password direct", DIRECT), ("Invalid password via WAF", PROTECTED)):
        status, body, error = request(base, "/rest/user/login", invalid)
        email, _ = identity(body)
        record(label, status == 401 and email is None, status, error or "Expected backend authentication rejection (401)")

    if args.skip_logs:
        print("[SKIP] Test 4 - CRS log attribution (not verified)")
    else:
        passed, detail, log_evidence = check_waf_log(run_id + "-waf", since)
        record("Test 4 - CRS log attribution", passed, log_evidence.get("http_status"), detail)

    report = {
        "started_at_utc": since, "run_id": run_id,
        "direct_url": DIRECT, "waf_url": PROTECTED,
        "results": results, "waf_log_evidence": log_evidence,
        "log_check_skipped": args.skip_logs,
        "all_executed_checks_passed": all(row["passed"] for row in results),
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("Results saved to " + str(args.output))
    passed_count = sum(row["passed"] for row in results)
    print(f"\nResult: {passed_count}/{len(results)} executed checks passed." + (" Log attribution SKIPPED." if args.skip_logs else ""))
    return 0 if report["all_executed_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
