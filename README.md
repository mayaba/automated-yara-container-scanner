# OSINT YARA Sweep for Containers

Minimal workflow to automatically fetch recent community YARA rules from Abuse.ch YARAify and scan a container’s filesystem. Supports copying a specific path from a running container (fast) or exporting the entire filesystem (thorough). Prints the combined rule text, recursively lists the target directory, and highlights files that matched.

## What this does
- Calls YARAify API at `https://yaraify-api.abuse.ch/api/v1/` with your `Auth-Key`
- Lists recent rules, skips entries where `rule_name == "classified"`
- Optionally limits to top-N non-classified rules
- Fetches raw YARA text per UUID, concatenates into one temporary `.yar`
- Copies a path from the container (or exports full FS), lists it, and runs `yara -r`
- Prints matched files for quick triage

## Repo contents
- `fetch_export_and_scan.py` — Python script that fetches rules and scans
- `Dockerfile` — Sample container that contains strings designed to match the GenericGh0st rule
- `detection_workflow_case_study.tex` — One-page, two-column LaTeX report (optional)

## Prerequisites
- Docker Desktop (or compatible Docker engine)
- YARA CLI
- Python 3.9+ and a virtual environment

## YARAify API access
- Get an `Auth-Key` from Abuse.ch YARAify (required). URL to obtain an Auth-Key: `https://yaraify.abuse.ch/api/#auth_key`.
- The script is locked to the official endpoint `https://yaraify-api.abuse.ch/api/v1/`.

## Quick start: test container and scan

1) Build the minimal test container (matches GenericGh0st rule):

```zsh
docker build -t yara-sample:latest .
```

2) Run the container:

```zsh
docker rm -f yara-sample 2>/dev/null || true
docker run -d --name yara-sample yara-sample
```

3) Run the script in cp mode (fast):

```zsh
source .venv/bin/activate
python fetch_export_and_scan.py \
	--container yara-sample \
	--auth "YOUR_AUTH_KEY" \
	--target-type cp \
	--container-path /app \
	--limit 20
```

Expected output includes:
- Combined YARA rules (printed)
- Recursive directory listing of the copied path (printed)
- YARA matches and a clean list of files with hits

## Full filesystem export (optional)

```zsh
python fetch_export_and_scan.py \
	--container yara-sample \
	--auth "$YOUR_AUTH_KEY" \
	--target-type export \
	--limit 10
```

## CLI flags
- `--auth` (string): Your YARAify Auth-Key (required)
- `--limit, -n` (int, default: 20): Top-N recent non-classified rules to fetch
- `--container, -c` (string): Running container name or ID
- `--target-type, -m` (export|cp): Scan method
	- `cp`: `docker cp` only a specific path from the container
	- `export`: `docker export` the entire container filesystem and extract
- `--container-path, -p` (string): Required when using `--target-type cp` (e.g., `/app`)

## How it works (high-level)
1. `recent_yararules` → list recent rule metadata (requires Auth-Key)
2. Filter out `rule_name == "classified"` and apply top-N `--limit`
3. For each UUID, call `get_yara_rule` → raw YARA text
4. Concatenate rules, print them, and write to a temp `.yar`
5. Copy or export target files from the container
6. Recursively list the target directory
7. Run `yara -r <rules.yar> <target>` and print files with matches

## Troubleshooting
- `urllib3 NotOpenSSLWarning` on macOS (LibreSSL vs OpenSSL):
	- Recommended: use Homebrew Python (OpenSSL 3):
		```zsh
		brew install python@3.12
		python3.12 -m venv .venv
		source .venv/bin/activate
		pip install -U pip requests
		```
	- Quick workaround: pin urllib3<2 in venv:
		```zsh
		pip install 'urllib3<2'
		```
- `yara: command not found`: install with `brew install yara` and ensure it’s in PATH.
- `docker: command not found`: install Docker Desktop and start the daemon.
- Empty ruleset: verify your `--auth` is correct and you have non-classified recent rules. Try increasing `--limit`.

## Security notes
- Treat rule sources as code: review before persistent adoption.
- Avoid scanning sensitive directories without proper authorization.
- Consider adding TLP filters and allow/deny lists for production use.

## License and attribution
- YARA rules fetched from YARAify are subject to their original licenses.
- This script is provided as-is for demonstration purposes.
