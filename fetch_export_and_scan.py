#!/usr/bin/env python3
"""
Minimal demo:
 - fetch YARA rules from a URL (optionally with an Auth-Key header)
 - for abuse.ch YARAify, POST JSON like the curl examples to list recent rules
     and then fetch each rule by UUID, skipping any that are classified
 - export a running container filesystem (or docker cp a path)
 - extract container filesystem to a temp dir
 - run `yara -r` against the extracted filesystem or copied path
 - cleanup temp files

Usage examples:
  # Export entire container filesystem (recommended)
  python fetch_export_and_scan.py --container my-running-container --target-type export

  # Only copy a specific path from container (smaller, faster)
  python fetch_export_and_scan.py --container my-running-container --target-type cp --container-path /app

    # With an auth key
    python fetch_export_and_scan.py --container my-running-container --auth "MY_KEY" --target-type export
"""

import argparse
import os
import sys
import tempfile
import requests
import tarfile
import subprocess
import shutil
from typing import List, Dict, Optional

API_URL = "https://yaraify-api.abuse.ch/api/v1/"

# ----------------------------
# Helper functions
# Implements the abuse.ch YARAify API semantics like the provided curl examples.
#   List recent rule metadata: {"query":"recent_yararules"}
#   Fetch rule by UUID: {"query":"get_yara_rule","uuid":"..."}
# Skip any entries whose rule_name is "classified".
# ----------------------------

def _post_json(url: str, payload: Dict, auth_key: Optional[str], timeout: int = 30):
    headers = {"Accept": "application/json"}
    if auth_key:
        headers["Auth-Key"] = auth_key
    # Use json= to send proper application/json; abuse.ch also accepts raw -d
    return requests.post(url, headers=headers, json=payload, timeout=timeout)


def _fetch_yaraify_recent(url: str, auth_key: Optional[str]) -> List[Dict]:
    resp = _post_json(url, {"query": "recent_yararules"}, auth_key)
    resp.raise_for_status()
    data = resp.json()
    if data.get("query_status") != "ok":
        raise RuntimeError(f"YARAify query_status not ok: {data.get('query_status')}")
    items = data.get("data") or []
    return [i for i in items if isinstance(i, dict)]


def _fetch_yaraify_rule_text(url: str, uuid: str, auth_key: Optional[str]) -> str:
    # This endpoint returns raw YARA text, not JSON
    headers = {}
    if auth_key:
        headers["Auth-Key"] = auth_key
    resp = requests.post(url, headers=headers, json={"query": "get_yara_rule", "uuid": uuid}, timeout=30)
    resp.raise_for_status()
    return resp.text.strip()


def fetch_rules(auth_key: Optional[str], limit: Optional[int] = None) -> str:
    """
    Build rules from the YARAify API only.
    """
    return assemble_yaraify_rules(API_URL, auth_key, limit=limit)


def assemble_yaraify_rules(url: str, auth_key: Optional[str], limit: Optional[int] = None) -> str:
    items = _fetch_yaraify_recent(url, auth_key)
    total = len(items)
    non_classified = [i for i in items if i.get("rule_name") and i.get("rule_name") != "classified"]
    classified_skipped = total - len(non_classified)
    allowed = non_classified
    limited_skipped = 0
    if limit and limit > 0:
        limited_skipped = max(0, len(non_classified) - min(len(non_classified), limit))
        allowed = non_classified[:limit]
    if classified_skipped or limited_skipped:
        msg_parts = []
        if classified_skipped:
            msg_parts.append(f"{classified_skipped} classified")
        if limited_skipped:
            msg_parts.append(f"{limited_skipped} over limit")
        print(f"[+] Skipped {', '.join(msg_parts)}; {len(allowed)} candidates remain")
    if not allowed:
        raise RuntimeError("No non-classified YARAify rules available")
    rules_texts: List[str] = []
    for it in allowed:
        uuid = it.get("yarahub_uuid") or it.get("uuid")
        if not uuid:
            continue
        try:
            rt = _fetch_yaraify_rule_text(url, uuid, auth_key)
            if rt:
                rules_texts.append(rt)
        except requests.HTTPError as e:
            print(f"[warn] Failed to fetch rule {uuid}: {e}", file=sys.stderr)
            continue
    if not rules_texts:
        raise RuntimeError("Fetched 0 rule texts from YARAify")
    return "\n\n".join(rules_texts)

def write_temp_rules(rules_text: str, tmpdir: str) -> str:
    if not rules_text or not rules_text.strip():
        raise ValueError("No rule text fetched.")
    out = os.path.join(tmpdir, "fetched_rules.yar")
    with open(out, "w", encoding="utf-8") as f:
        f.write(rules_text)
    return out

def print_combined_rules(rules_text: str) -> None:
    print("\n=== Combined YARA rules to be executed ===")
    print(rules_text)
    print("=== End of combined YARA rules ===\n")

def docker_export_container(container: str, out_tar: str) -> None:
    cmd = ["docker", "export", "-o", out_tar, container]
    subprocess.run(cmd, check=True)

def docker_cp_path(container: str, container_path: str, out_dir: str) -> str:
    # docker cp <container>:<path> <hostpath>
    dest = os.path.join(out_dir, os.path.basename(container_path.strip("/")) or "copied_path")
    cmd = ["docker", "cp", f"{container}:{container_path}", dest]
    subprocess.run(cmd, check=True)
    return dest

def extract_tar(tar_path: str, extract_to: str) -> None:
    with tarfile.open(tar_path, "r") as tf:
        tf.extractall(path=extract_to)

def run_yara(rules_path: str, target_path: str) -> tuple[int, List[dict], List[str]]:
    """Run yara recursively, return (exit_code, matches, matched_files).

    matches: list of {"rule": str, "file": str}
    matched_files: unique file paths with hits
    """
    cmd = ["yara", "-r", rules_path, target_path]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    raw = proc.stdout.strip() if proc.stdout else ""
    matches: List[dict] = []
    matched_files: List[str] = []
    if raw:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # YARA default: "<rule> <file>"; file path may contain spaces, rule name cannot.
            parts = line.split(" ", 1)
            if len(parts) == 2:
                rule, fpath = parts[0], parts[1]
                matches.append({"rule": rule, "file": fpath})
                if fpath not in matched_files:
                    matched_files.append(fpath)
    # Print same sections as before
    if raw:
        print("\n--- YARA MATCHES ---")
        print(raw)
    else:
        print("\nNo matches found.")
    if proc.stderr:
        print("\n--- YARA STDERR ---", file=sys.stderr)
        print(proc.stderr.strip(), file=sys.stderr)
    return proc.returncode, matches, matched_files

def list_directory_tree(path: str) -> None:
    """Recursively list directory contents similar to ls -R (lightweight)."""
    print("\n=== Listing scan target (recursive) ===")
    base = os.path.abspath(path)
    for root, dirs, files in os.walk(base):
        rel_root = os.path.relpath(root, base)
        header = base if rel_root == "." else os.path.join(base, rel_root)
        print(f"{header}:")
        for d in sorted(dirs):
            print(f"  [D] {d}/")
        for f in sorted(files):
            fpath = os.path.join(root, f)
            try:
                size = os.path.getsize(fpath)
            except OSError:
                size = 0
            print(f"  [F] {f} ({size} bytes)")
        print("")
    print("=== End of listing ===\n")

def check_prereqs():
    for cmd in ("docker", "yara"):
        if not shutil.which(cmd):
            print(f"ERROR: required command '{cmd}' not found on PATH. Install it first.", file=sys.stderr)
            return False
    try:
        import requests  # quick check
    except Exception:
        print("ERROR: python package 'requests' not installed. Run: pip install requests", file=sys.stderr)
        return False
    return True

# ----------------------------
# Main
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="Fetch YARA rules, export/cp container, run yara scan.")
    parser.add_argument("--auth", "-a", default=None, help="Optional Auth-Key header value")
    parser.add_argument("--limit", "-n", type=int, default=20, help="Limit number of recent non-classified rules (top-N)")
    parser.add_argument("--container", "-c", required=True, help="Container name or ID to inspect")
    parser.add_argument("--target-type", "-m", choices=("export", "cp"), default="export",
                        help="export: docker export full fs (default). cp: docker cp a path (faster)")
    parser.add_argument("--container-path", "-p", default=None,
                        help="When using --target-type cp, the path inside container to copy (example: /app). Required for cp.")
    args = parser.parse_args()

    if not check_prereqs():
        sys.exit(2)

    tmpdir = tempfile.mkdtemp(prefix="contscan_")
    rules_file = None
    container_tar = None
    extracted_fs = None

    try:
        print(f"[+] Fetching rules from {API_URL} ...")
        rules_text = fetch_rules(args.auth, limit=args.limit)
        if not rules_text.strip():
            print("ERROR: fetched empty ruleset", file=sys.stderr)
            sys.exit(3)
        # Show the combined rules and write them to a temp file
        print_combined_rules(rules_text)
        rules_file = write_temp_rules(rules_text, tmpdir)
        print(f"[+] Wrote rules to {rules_file}")

        if args.target_type == "export":
            container_tar = os.path.join(tmpdir, f"{args.container}.tar")
            print(f"[+] Exporting container '{args.container}' to tar: {container_tar} (this may take a moment)")
            docker_export_container(args.container, container_tar)
            extracted_fs = os.path.join(tmpdir, "fs")
            os.makedirs(extracted_fs, exist_ok=True)
            print(f"[+] Extracting tar to {extracted_fs} ...")
            extract_tar(container_tar, extracted_fs)
            scan_target = extracted_fs
        else:
            # cp mode
            if not args.container_path:
                print("ERROR: --container-path is required when --target-type cp", file=sys.stderr)
                sys.exit(4)
            print(f"[+] Copying path '{args.container_path}' from container '{args.container}' ...")
            copied = docker_cp_path(args.container, args.container_path, tmpdir)
            print(f"[+] Copied to {copied}")
            scan_target = copied

        # List the target directory recursively before scanning
        if os.path.isdir(scan_target):
            list_directory_tree(scan_target)

        print(f"[+] Running yara against: {scan_target}")
        rc, _, matched_files = run_yara(rules_file, scan_target)
        if matched_files:
            print("\n=== Files with matches ===")
            for f in matched_files:
                print(f)
            print("=== End matched files ===")

            # Print the contents of matched files
            print("\n=== Contents of matched files ===")
            for f in matched_files:
                print(f"\n--- File: {f} ---")
                try:
                    with open(f, "r", encoding="utf-8", errors="replace") as mf:
                        content = mf.read()
                        print(content)
                except Exception as e:
                    print(f"[warn] Could not read file {f}: {e}", file=sys.stderr)
            print("=== End of matched files contents ===\n")

        print(f"[+] YARA exit code: {rc}")
    except subprocess.CalledProcessError as e:
        print("ERROR: subprocess failed:", e, file=sys.stderr)
        sys.exit(5)
    except requests.HTTPError as e:
        print("ERROR: HTTP error while fetching rules:", e, file=sys.stderr)
        sys.exit(6)
    except Exception as e:
        print("ERROR: unexpected error:", e, file=sys.stderr)
        sys.exit(7)
    finally:
        # cleanup
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

    sys.exit(0)


if __name__ == "__main__":
    main()
