#!/usr/bin/env python3
"""
API VAPT Tool — CLI Postman Collection Runner
Automates target onboarding, consent verification, Postman collection & environment parsing,
scan launching, live progress tracking, and report generation.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error


def parse_postman_env(env_path: str) -> dict[str, str]:
    """Parse Postman environment JSON and extract key-value mapping."""
    if not env_path or not os.path.exists(env_path):
        return {}
    with open(env_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    variables = {}
    # Postman environment format has values in 'values' list
    for item in data.get("values", []):
        if item.get("enabled", True):
            variables[item.get("key", "")] = str(item.get("value", ""))
    return variables


def substitute_postman_variables(content: str, variables: dict[str, str]) -> str:
    """Replace {{variable}} occurrences with environment values."""
    for key, val in variables.items():
        if key:
            pattern = re.compile(r"\{\{\s*" + re.escape(key) + r"\s*\}\}")
            content = pattern.sub(val, content)
    return content


def make_request(url: str, method: str = "GET", data: dict | None = None) -> dict:
    """Helper to send JSON HTTP requests without external dependencies."""
    headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8")
            return json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        print(f"[-] HTTP Error {e.code} on {url}: {err_msg}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[-] Connection Error on {url}: {e.reason}")
        print("[-] Ensure the backend is running (uvicorn main:app --port 8000)")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Run API VAPT scan using a Postman Collection and optional Environment JSON."
    )
    parser.add_argument("--collection", "-c", required=True, help="Path to Postman collection JSON file")
    parser.add_argument("--env", "-e", required=False, default=None, help="Path to Postman environment JSON file")
    parser.add_argument("--url", "-u", required=False, default=None, help="Target Base URL (overrides collection host if provided)")
    parser.add_argument("--name", "-n", required=False, default="Postman API Scan", help="Scan name")
    parser.add_argument("--mode", "-m", choices=["safe", "full"], default="safe", help="Scan mode: safe (read-only/low impact) or full (active fuzzing)")
    parser.add_argument("--api-server", default="http://localhost:8000", help="VAPT Tool API Server URL")
    parser.add_argument("--download-report", action="store_true", default=True, help="Download HTML report upon completion")

    args = parser.parse_args()

    if not os.path.exists(args.collection):
        print(f"[-] Collection file not found: {args.collection}")
        sys.exit(1)

    print("=" * 65)
    print("      🛡️  API VAPT TOOL — POSTMAN COLLECTION SCANNER 🛡️")
    print("=" * 65)

    # 1. Load and substitute variables
    print(f"[*] Reading Postman collection: {args.collection}")
    with open(args.collection, "r", encoding="utf-8") as f:
        raw_collection = f.read()

    variables = {}
    if args.env:
        print(f"[*] Reading Postman environment: {args.env}")
        variables = parse_postman_env(args.env)
        print(f"[+] Loaded {len(variables)} environment variable(s).")
        raw_collection = substitute_postman_variables(raw_collection, variables)

    # Detect base URL if not explicitly supplied
    base_url = args.url
    if not base_url:
        # Check if environment provided baseUrl
        base_url = variables.get("baseUrl") or variables.get("base_url") or variables.get("url")
        if not base_url:
            # Try to infer from collection items
            try:
                coll_json = json.loads(raw_collection)
                # Check variable in collection
                for v in coll_json.get("variable", []):
                    if v.get("key") in ("baseUrl", "base_url", "url") and v.get("value"):
                        base_url = v["value"]
                        break
            except Exception:
                pass

    if not base_url:
        base_url = "http://localhost:8080"
        print(f"[!] No base URL specified or detected in env; defaulting to: {base_url}")
    else:
        print(f"[+] Target Base URL: {base_url}")

    api = args.api_server.rstrip("/")

    # Check health
    health = make_request(f"{api}/api/health")
    print(f"[+] Connected to VAPT Tool backend: {health}")

    # 2. Register Target
    print("\n[*] Step 1/3: Registering target...")
    target_data = {
        "name": f"Target: {args.name}",
        "base_url": base_url,
        "description": f"Automated scan of {os.path.basename(args.collection)}",
        "allowed_domains": [base_url.split("://")[-1].split("/")[0].split(":")[0]],
    }
    target = make_request(f"{api}/api/targets/", method="POST", data=target_data)
    target_id = target["id"]
    print(f"[+] Target registered with ID: {target_id}")

    # 3. Create Consent Record (Security authorization gate)
    print("[*] Step 2/3: Signing consent authorization record...")
    consent_data = {
        "target_id": target_id,
        "tester_name": "CLI Security Auditor",
        "tester_email": "auditor@local",
        "authorization_statement": "I confirm written authorization to test this target.",
        "scope_description": f"Authorized security testing via Postman collection: {os.path.basename(args.collection)}",
    }
    consent = make_request(f"{api}/api/targets/{target_id}/consent", method="POST", data=consent_data)
    consent_id = consent["id"]
    print(f"[+] Consent signed with ID: {consent_id}")

    # 4. Launch Scan
    print("\n[*] Step 3/3: Launching VAPT scan...")
    scan_payload = {
        "target_id": target_id,
        "consent_id": consent_id,
        "name": args.name,
        "mode": args.mode,
        "spec_type": "postman",
        "spec_content": raw_collection,
        "rate_limit_rps": 5.0,
        "concurrency": 4,
        "timeout": 20.0,
    }
    scan = make_request(f"{api}/api/scans/", method="POST", data=scan_payload)
    scan_id = scan["id"]
    print(f"[+] Scan successfully started with ID: {scan_id}")

    # 5. Monitor progress
    print("\n[*] Monitoring scan progress...")
    while True:
        status_info = make_request(f"{api}/api/scans/{scan_id}")
        status = status_info.get("status")
        progress = status_info.get("progress_pct", 0)
        tested = status_info.get("tested_endpoints", 0)
        total = status_info.get("total_endpoints", 0)

        sys.stdout.write(f"\r[-] Status: {status.upper()} | Progress: {progress:.1f}% ({tested}/{total} endpoints tested)")
        sys.stdout.flush()

        if status in ("completed", "failed", "cancelled"):
            print()
            break
        time.sleep(1.5)

    if status == "completed":
        print("\n[+] Scan completed successfully!")
        findings = make_request(f"{api}/api/scans/{scan_id}/findings")
        print(f"[+] Total vulnerabilities found: {len(findings)}")

        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        print("\n--- Vulnerability Summary ---")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in severity_counts:
                print(f"  [{sev}]: {severity_counts[sev]}")

        # Download HTML report
        if args.download_report:
            report_url = f"{api}/api/reports/{scan_id}/html"
            output_file = f"vapt_report_{scan_id[:8]}.html"
            print(f"\n[*] Downloading HTML Report: {report_url}")
            try:
                urllib.request.urlretrieve(report_url, output_file)
                print(f"[+] Report saved to: {os.path.abspath(output_file)}")
            except Exception as e:
                print(f"[-] Could not download report: {e}")
    else:
        print(f"\n[-] Scan ended with status: {status}")
        if status_info.get("error_message"):
            print(f"[-] Error: {status_info['error_message']}")


if __name__ == "__main__":
    main()
