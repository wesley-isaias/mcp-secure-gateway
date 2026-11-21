import json
import os

import pytest

from mcp_secure_gateway.audit import AuditError, AuditLog, pseudonym, verify

KEY = b"k" * 32


def _write(log_path, n=3):
    log = AuditLog(log_path, KEY)
    for i in range(n):
        log.append(client="c1", tool="list_fixtures", decision="allowed", reason=f"r{i}")
    return log


def _lines(path):
    return path.read_text().splitlines()


def test_chain_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path)
    result = verify(path, KEY)
    assert result.ok and result.records == 3


def test_file_is_private(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, 1)
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_reopen_continues_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, 2)
    _write(path, 2)
    result = verify(path, KEY)
    assert result.ok and result.records == 4


def test_edited_field_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path)
    lines = _lines(path)
    record = json.loads(lines[1])
    record["decision"] = "denied"
    lines[1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")
    result = verify(path, KEY)
    assert not result.ok and result.error_line == 2 and result.reason == "MAC mismatch"


def test_deleted_line_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path)
    lines = _lines(path)
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    result = verify(path, KEY)
    assert not result.ok and result.error_line == 2


def test_reordered_lines_are_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path)
    lines = _lines(path)
    path.write_text("\n".join([lines[1], lines[0], lines[2]]) + "\n")
    assert not verify(path, KEY).ok


def test_forged_record_with_recomputed_seq_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, 1)
    first = json.loads(_lines(path)[0])
    forged = {**first, "seq": 2, "prev": first["mac"], "mac": "0" * 64}
    with path.open("a") as fh:
        fh.write(json.dumps(forged) + "\n")
    result = verify(path, KEY)
    assert not result.ok and result.reason == "MAC mismatch"


def test_wrong_key_fails(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path)
    assert not verify(path, b"x" * 32).ok


def test_extra_field_is_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, 1)
    record = json.loads(_lines(path)[0])
    record["arguments"] = {"fixture_id": "alpha"}
    path.write_text(json.dumps(record) + "\n")
    assert verify(path, KEY).reason == "unexpected fields"


def test_writer_refuses_to_start_on_tampered_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path)
    path.write_text(path.read_text().replace('"r1"', '"rx"'))
    with pytest.raises(AuditError, match="refusing to start"):
        AuditLog(path, KEY)


def test_short_key_is_rejected(tmp_path):
    with pytest.raises(AuditError):
        AuditLog(tmp_path / "a.jsonl", b"short")


@pytest.mark.parametrize("bad", ["Run Checks", "x" * 80, "../etc", ""])
def test_free_text_cannot_enter_the_log(tmp_path, bad):
    log = AuditLog(tmp_path / "a.jsonl", KEY)
    with pytest.raises(AuditError):
        log.append(client="c", tool=bad, decision="allowed", reason="allowed")


def test_unreadable_log_refuses_to_start(tmp_path):
    with pytest.raises(AuditError, match="cannot read"):
        AuditLog(tmp_path, KEY)  # a directory, not a file


def test_write_failure_raises(tmp_path):
    target = tmp_path / "audit.jsonl"
    log = AuditLog(target, KEY)
    target.mkdir()  # the log disappears and the path becomes unwritable
    with pytest.raises(AuditError, match="audit write failed"):
        log.append(client="c", tool="list_fixtures", decision="allowed", reason="allowed")


def test_pseudonym_is_stable_and_keyed():
    assert pseudonym(KEY, "ci-bot") == pseudonym(KEY, "ci-bot")
    assert pseudonym(KEY, "ci-bot") != pseudonym(b"z" * 32, "ci-bot")
    assert "ci-bot" not in pseudonym(KEY, "ci-bot")
