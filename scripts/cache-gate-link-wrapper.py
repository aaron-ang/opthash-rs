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
argv0 = os.environ.get(f"{prefix}_ARGV0", "")
trace_text = os.environ.get(f"{prefix}_TRACE", "")
role = os.environ.get(f"{prefix}_ROLE", "")
session = os.environ.get("CACHE_GATE_LINK_SESSION", "")
driver = Path(driver_text)
trace = Path(trace_text)
if (
    not driver.is_absolute()
    or not driver.is_file()
    or driver.is_symlink()
    or driver != driver.resolve()
):
    fail(f"{prefix}_DRIVER must be an absolute file")
if not argv0 or "\x00" in argv0:
    fail(f"{prefix}_ARGV0 must be non-empty")
if not trace.is_absolute() or not trace.parent.is_dir() or trace.is_symlink():
    fail(f"{prefix}_TRACE must name a new or regular file in an existing directory")
if bool(role) != bool(session):
    fail("link role and session must either both be set or both be empty")
arguments = sys.argv[1:]
if not inner:
    fragment_text = os.environ.get("CACHE_GATE_LINK_FRAGMENT", "")
    map_text = os.environ.get("CACHE_GATE_LINK_MAP", "")
    if bool(fragment_text) != bool(map_text):
        fail("CACHE_GATE_LINK_FRAGMENT and CACHE_GATE_LINK_MAP must be set together")
    if fragment_text:
        fragment = Path(fragment_text)
        link_map = Path(map_text)
        if (
            not fragment.is_absolute()
            or not fragment.is_file()
            or fragment.is_symlink()
            or fragment != fragment.resolve()
        ):
            fail("CACHE_GATE_LINK_FRAGMENT must be an absolute regular file")
        if (
            not link_map.is_absolute()
            or not link_map.parent.is_dir()
            or link_map.parent.is_symlink()
            or link_map.parent != link_map.parent.resolve()
            or link_map.is_symlink()
            or (link_map.exists() and not link_map.is_file())
        ):
            fail("CACHE_GATE_LINK_MAP must be an absolute regular-file path")
        arguments = [
            *arguments,
            f"-Wl,-T,{fragment}",
            f"-Wl,-Map,{link_map}",
        ]
record = {
    "payload_path": str(driver),
    "payload_sha256": hashlib.sha256(driver.read_bytes()).hexdigest(),
    "argv0": argv0,
    "argv": arguments,
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
compiler_environment = {"LC_ALL": "C", "PATH": record["path"]}
for variable in (
    "CACHE_GATE_INNER_LINK_DRIVER",
    "CACHE_GATE_INNER_LINK_ARGV0",
    "CACHE_GATE_INNER_LINK_TRACE",
    "CACHE_GATE_INNER_LINK_ROLE",
    "CACHE_GATE_LINK_SESSION",
):
    if variable in os.environ:
        compiler_environment[variable] = os.environ[variable]
os.execve(str(driver), [argv0, *arguments], compiler_environment)
