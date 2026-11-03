"""Cadena de integridad del log de auditoría (SOC 2 CC7.2, ISO 27701 6.9.4.2)."""

import io
import json
import logging

import pytest

from app.core import audit as audit_module
from app.core.audit import audit, verify_lines
from app.core.config import settings
from app.core.logging import JSONFormatter
from app.core.middleware import log_ip

KEY = "k" * 40


@pytest.fixture
def json_log(monkeypatch):
    """Captura los eventos de `app.audit` tal como saldrían en el log JSON."""
    monkeypatch.setattr(settings, "AUDIT_HMAC_KEY", type(settings.AUDIT_HMAC_KEY)(KEY))
    monkeypatch.setattr(audit_module, "_chain", audit_module._Chain())
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JSONFormatter())
    logger = logging.getLogger("app.audit")
    logger.addHandler(handler)
    previous = logger.level
    logger.setLevel(logging.INFO)
    yield stream
    logger.removeHandler(handler)
    logger.setLevel(previous)


def _emit(n: int = 3) -> None:
    for i in range(n):
        audit("test.event", user_id=f"u{i}", client_ip="203.0.113.7")


def test_chain_verifies(json_log):
    _emit()
    lines = json_log.getvalue().splitlines()
    report = verify_lines(lines, KEY.encode())
    assert report.ok and report.events == 3 and report.streams == 1
    first = json.loads(lines[0])
    assert first["audit_seq"] == 1 and first["audit_alg"] == "hmac-sha256"
    assert first["request_id"] and first["at"]


def test_tampered_event_is_detected(json_log):
    _emit()
    lines = json_log.getvalue().splitlines()
    record = json.loads(lines[1])
    record["user_id"] = "someone-else"
    lines[1] = json.dumps(record)
    report = verify_lines(lines, KEY.encode())
    assert not report.ok and "alterado" in report.errors[0]


def test_deleted_event_is_detected(json_log):
    _emit()
    lines = json_log.getvalue().splitlines()
    del lines[1]
    report = verify_lines(lines, KEY.encode())
    assert not report.ok and "faltan eventos" in report.errors[0]


def test_forged_chain_without_key_fails(json_log):
    """Quien no tiene la clave no puede recalcular los hashes tras editar un evento."""
    _emit(2)
    lines = json_log.getvalue().splitlines()
    report = verify_lines(lines, b"otra-clave-distinta-de-la-buena-123456")
    assert not report.ok


def test_rotated_fragment_is_a_note_not_an_error(json_log):
    _emit(3)
    lines = json_log.getvalue().splitlines()[1:]
    report = verify_lines(lines, KEY.encode())
    assert report.ok and report.notes


def test_short_audit_key_rejected():
    from pydantic import ValidationError

    from app.core.config import Settings

    with pytest.raises(ValidationError, match="AUDIT_HMAC_KEY"):
        Settings(AUDIT_HMAC_KEY="corta")


@pytest.mark.parametrize(
    ("mode", "ip", "expected"),
    [
        ("truncated", "203.0.113.77", "203.0.113.0/24"),
        ("truncated", "2001:db8:1:2::5", "2001:db8:1::/48"),
        ("full", "203.0.113.77", "203.0.113.77"),
        ("off", "203.0.113.77", None),
        ("truncated", "testclient", None),
    ],
)
def test_access_log_ip_minimization(monkeypatch, mode, ip, expected):
    monkeypatch.setattr(settings, "ACCESS_LOG_IP", mode)
    assert log_ip(ip) == expected
