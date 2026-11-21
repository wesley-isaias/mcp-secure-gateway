"""Tamper-evident, content-free audit log.

Each tool call produces one JSON line *before* the tool runs, and one more
with the outcome (``succeeded`` or ``failed``) after it returns::

    {"seq": 7, "ts": "...", "client": "3f1c...", "tool": "run_checks",
     "decision": "denied", "reason": "action_denied", "prev": "<mac of seq 6>",
     "mac": "<HMAC-SHA256 over this record without 'mac'>"}

* **Content-free:** tool arguments and results are never written. Client
  identifiers are pseudonymised with a keyed hash.
* **Chained:** every record carries the MAC of the previous one, so editing,
  deleting, inserting or reordering lines breaks verification.
* **Fail closed:** if the record cannot be written and flushed to disk, the
  caller must refuse the action.

Limit: removing lines from the *end* of the file cannot be detected by the
chain alone. Production systems export periodic checkpoints (last ``seq`` and
``mac``) to write-once storage; see the README.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

GENESIS = "0" * 64
DECISIONS = frozenset({"allowed", "denied", "rate_limited", "succeeded", "failed"})
_FIELDS = ("seq", "ts", "client", "tool", "decision", "reason", "prev")
_TOKEN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class AuditError(RuntimeError):
    """The audit log could not be written or its existing chain is invalid."""


def _canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _mac(key: bytes, record: dict) -> str:
    body = {k: record[k] for k in _FIELDS}
    return hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()


def pseudonym(key: bytes, client_id: str) -> str:
    """Stable, non-reversible client label for the log (16 hex chars)."""
    return hmac.new(key, b"client:" + client_id.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def load_key(path: Path) -> bytes:
    """Read an audit key file. The key must be at least 32 bytes."""
    key = path.read_bytes().strip()
    if len(key) < 32:
        raise AuditError("audit key must be at least 32 bytes")
    return key


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    last_mac: str
    error_line: int | None = None
    reason: str | None = None


def verify(path: Path, key: bytes) -> VerifyResult:
    """Check every record's schema, sequence, chain link and MAC."""
    prev = GENESIS
    count = 0
    if not path.exists():
        return VerifyResult(True, 0, GENESIS)
    try:
        fh = path.open("r", encoding="utf-8")
    except OSError as exc:
        raise AuditError(f"cannot read audit log: {exc.strerror}") from exc
    with fh:
        for lineno, line in enumerate(fh, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return VerifyResult(False, count, prev, lineno, "not valid JSON")
            if not isinstance(record, dict) or set(record) != {*_FIELDS, "mac"}:
                return VerifyResult(False, count, prev, lineno, "unexpected fields")
            if record["seq"] != count + 1:
                return VerifyResult(False, count, prev, lineno, "sequence gap or reorder")
            if record["prev"] != prev:
                return VerifyResult(False, count, prev, lineno, "broken chain link")
            if not hmac.compare_digest(record["mac"], _mac(key, record)):
                return VerifyResult(False, count, prev, lineno, "MAC mismatch")
            prev = record["mac"]
            count += 1
    return VerifyResult(True, count, prev)


class AuditLog:
    """Append-only writer. Verifies the existing chain before accepting events."""

    def __init__(self, path: Path, key: bytes, clock=lambda: datetime.now(UTC)):
        if len(key) < 32:
            raise AuditError("audit key must be at least 32 bytes")
        self._path = path
        self._key = key
        self._clock = clock
        self._lock = threading.Lock()
        existing = verify(path, key)
        if not existing.ok:
            raise AuditError(
                f"refusing to start: audit log invalid at line {existing.error_line} "
                f"({existing.reason})"
            )
        self._seq = existing.records
        self._prev = existing.last_mac

    @property
    def key(self) -> bytes:
        return self._key

    def append(self, *, client: str, tool: str, decision: str, reason: str) -> int:
        """Write one record and fsync it. Raises AuditError on any failure."""
        if decision not in DECISIONS:
            raise AuditError(f"unknown decision: {decision}")
        if not _TOKEN.match(tool) or not _TOKEN.match(reason):
            raise AuditError("tool and reason must be short lowercase identifiers")
        with self._lock:
            record = {
                "seq": self._seq + 1,
                "ts": self._clock().isoformat(timespec="milliseconds"),
                "client": client,
                "tool": tool,
                "decision": decision,
                "reason": reason,
                "prev": self._prev,
            }
            record["mac"] = _mac(self._key, record)
            line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            try:
                fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    os.write(fd, line.encode("utf-8"))
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError as exc:
                raise AuditError(f"audit write failed: {exc.strerror}") from exc
            self._seq = record["seq"]
            self._prev = record["mac"]
            return self._seq
