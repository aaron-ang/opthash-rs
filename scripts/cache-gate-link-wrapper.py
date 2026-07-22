#!/usr/bin/env python3
"""Record every cache-gate linker invocation, then exec the probed driver."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"cache-gate link wrapper: {message}", file=sys.stderr)
    raise SystemExit(2)


inner = Path(sys.argv[0]).name in {"ld.bfd", "ld.lld"}
prefix = "CACHE_GATE_INNER_LINK" if inner else "CACHE_GATE_LINK"
driver_text = os.environ.get(f"{prefix}_DRIVER", "")
trace_text = os.environ.get(f"{prefix}_TRACE", "")
role = os.environ.get(f"{prefix}_ROLE", "")
session = os.environ.get("CACHE_GATE_LINK_SESSION", "")
driver = Path(driver_text)
trace = Path(trace_text)
if not driver.is_absolute() or not driver.is_file():
    fail(f"{prefix}_DRIVER must be an absolute file")
if not trace.is_absolute() or not trace.parent.is_dir() or trace.is_symlink():
    fail(f"{prefix}_TRACE must name a new or regular file in an existing directory")
if bool(role) != bool(session):
    fail("link role and session must either both be set or both be empty")
driver = driver.resolve()
record = {
    "driver": str(driver),
    "driver_sha256": hashlib.sha256(driver.read_bytes()).hexdigest(),
    "argv": sys.argv[1:],
    "cwd": str(Path.cwd().resolve()),
    "path": os.environ.get("PATH", ""),
}
if role:
    record["role"] = role
    record["session"] = session
with trace.open("a", encoding="utf-8") as stream:
    fcntl.flock(stream, fcntl.LOCK_EX)
    stream.write(json.dumps(record, sort_keys=True) + "\n")
    stream.flush()
    os.fsync(stream.fileno())
    fcntl.flock(stream, fcntl.LOCK_UN)
os.execv(str(driver), [str(driver), *sys.argv[1:]])
