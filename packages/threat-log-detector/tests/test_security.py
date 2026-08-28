"""DevSecOps Security & CWE Hardening Tests."""

import ast
import os
from pathlib import Path
import pytest

from detector.alerting import AlertGenerator, sanitize_text
from detector.engine import AnomalyScoreResult
from detector.features import SlidingWindowBuffer
from detector.parser import EventType, LogEvent, LogParser, SourceType


SRC_DIR = Path(__file__).parent.parent / "src" / "detector"


def test_cwe_502_zero_pickle_imports_in_source() -> None:
    """Invariant: PROHIBIT pickle and joblib.load across all source modules (CWE-502)."""
    for py_file in SRC_DIR.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        parsed = ast.parse(content, filename=str(py_file))
        for node in ast.walk(parsed):
            # Check import statements
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "pickle", f"Forbidden import 'pickle' found in {py_file}"
                    assert alias.name != "_pickle", f"Forbidden import '_pickle' found in {py_file}"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "pickle", f"Forbidden 'from pickle' import found in {py_file}"
                assert node.module != "_pickle", f"Forbidden 'from _pickle' import found in {py_file}"
                if node.module == "joblib":
                    for alias in node.names:
                        assert alias.name != "load", f"Forbidden 'joblib.load' found in {py_file}"


def test_cwe_798_zero_hardcoded_secrets_in_source() -> None:
    """Verify absence of real hardcoded credentials in source code (CWE-798)."""
    forbidden_values = [
        "gh" + "p_1234567890abcdef1234567890abcdef",
        "sk_" + "live_1234567890abcdef123456",
        "AK" + "IAIOSFODNN7EXAMPLE",
        "wJ" + "alrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ]
    for py_file in SRC_DIR.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for val in forbidden_values:
            assert val not in content, f"Hardcoded secret {val} found in {py_file}"


def test_cwe_209_pii_and_password_redaction() -> None:
    """Ensure credentials, bearer tokens, and private keys are redacted to [REDACTED] (CWE-209)."""
    fake_sk = "sk_" + "live_51Mz98124891248912489124891248912489"
    sensitive_samples = [
        ("Login failed password=SuperSecretPassword123! from 1.1.1.1", "password=[REDACTED]"),
        ("Header: Authorization: Bearer abcdef1234567890abcdef123456", "Bearer [REDACTED]"),
        (f"Key: {fake_sk}", "[REDACTED]"),
    ]
    for raw, expected in sensitive_samples:
        clean = sanitize_text(raw)
        assert expected in clean
        assert "SuperSecretPassword123!" not in clean
        assert "abcdef1234567890" not in clean


def test_cwe_400_buffer_dos_mitigation() -> None:
    """Ensure sliding window buffer enforces max_events capacity to prevent memory exhaustion (CWE-400)."""
    buf = SlidingWindowBuffer(window_seconds=3600.0, max_events=100)
    for i in range(500):
        buf.add(LogEvent(
            timestamp=LogParser().parse_line("").timestamp,
            source_type=SourceType.GENERIC,
            event_type=EventType.GENERIC_EVENT,
        ))
    assert len(buf) == 100


def test_cwe_400_max_line_length_log_bomb_mitigation() -> None:
    """Ensure parser gracefully truncates and tags oversized log lines without memory spikes (CWE-400)."""
    parser = LogParser()
    bomb = "A" * 100_000
    ev = parser.parse_line(bomb)
    assert ev.event_type == EventType.MALFORMED
    assert ev.status == "line_too_long"
    assert len(ev.raw_message) < 500
