#!/usr/bin/env python3
"""Timestamp wrapper — prefixes every output line with elapsed seconds."""
import subprocess, sys, time

if len(sys.argv) < 2:
    print("Usage: ts-run.py <command> [args...]", file=sys.stderr)
    sys.exit(1)

proc = subprocess.Popen(
    sys.argv[1:],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
)
start = time.time()
for line in proc.stdout:
    elapsed = time.time() - start
    print(f"[{elapsed:7.1f}s] {line}", end="", flush=True)
proc.wait()
sys.exit(proc.returncode)
