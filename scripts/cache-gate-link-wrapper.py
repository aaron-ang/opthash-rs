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


driver_text = os.environ.get("CACHE_GATE_LINK_DRIVER", "")
trace_text = os.environ.get("CACHE_GATE_LINK_TRACE", "")
driver = Path(driver_text)
trace = Path(trace_text)
if not driver.is_absolute() or not driver.is_file():
    fail("CACHE_GATE_LINK_DRIVER must be an absolute file")
if not trace.is_absolute() or not trace.parent.is_dir() or trace.is_symlink():
    fail(
        "CACHE_GATE_LINK_TRACE must name a new or regular file in an existing directory"
    )
driver = driver.resolve()
record = {
    "driver": str(driver),
    "driver_sha256": hashlib.sha256(driver.read_bytes()).hexdigest(),
    "argv": sys.argv[1:],
    "cwd": str(Path.cwd().resolve()),
    "path": os.environ.get("PATH", ""),
}
with trace.open("a", encoding="utf-8") as stream:
    fcntl.flock(stream, fcntl.LOCK_EX)
    stream.write(json.dumps(record, sort_keys=True) + "\n")
    stream.flush()
    os.fsync(stream.fileno())
    fcntl.flock(stream, fcntl.LOCK_UN)
os.execv(str(driver), [str(driver), *sys.argv[1:]])
