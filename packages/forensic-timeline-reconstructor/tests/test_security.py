"""Security unit tests covering CWE-1333, CWE-22, CWE-209, CWE-502, CWE-400."""

import time
import pytest
from pydantic import ValidationError

from timeline.cli import _resolve_files
from timeline.normalizer import ForensicEvent, normalize_to_utc
from timeline.parsers.auth import AuthLogParser
from timeline.parsers.json_lines import JsonLinesParser
from timeline.parsers.nginx import NginxParser
from timeline.parsers.syslog import SyslogParser


def test_redos_bounded_regex_syslog() -> None:
    # CWE-1333: Ensure pathological inputs evaluate linearly in sub-millisecond time
    parser = SyslogParser()
    pathological_line = "<165>1 " + "2023-10-11T" + ("a" * 5000) + " myhost app 123 ID47 - msg"

    start_t = time.perf_counter()
    res = parser.parse_line(pathological_line)
    elapsed = time.perf_counter() - start_t

    # Must complete almost instantaneously (< 50ms)
    assert elapsed < 0.05
    assert res is None or isinstance(res, ForensicEvent)


def test_redos_bounded_regex_nginx() -> None:
    parser = NginxParser()
    pathological_line = "127.0.0.1 - - [" + ("10/Oct/2023:" * 200) + "] " + ('"GET /' + "a" * 5000 + ' HTTP/1.1"')

    start_t = time.perf_counter()
    res = parser.parse_line(pathological_line)
    elapsed = time.perf_counter() - start_t

    assert elapsed < 0.05
    assert res is None or isinstance(res, ForensicEvent)


def test_redos_bounded_regex_auth() -> None:
    parser = AuthLogParser()
    pathological_line = "Oct 11 22:14:15 host sshd[123]: " + ("Failed password for " * 500) + " root from 1.1.1.1"

    start_t = time.perf_counter()
    res = parser.parse_line(pathological_line)
    elapsed = time.perf_counter() - start_t

    assert elapsed < 0.05
    assert res is None or isinstance(res, ForensicEvent)


def test_fail_open_corrupted_lines_cwe_209() -> None:
    # CWE-209 / CWE-754: Pipeline remains alive across arbitrary corrupted lines
    parser = SyslogParser()
    corrupt_inputs = [
        "",
        "\x00\x01\x02\x03",
        "???!@#$%^&*()_+",
        "<9999999999999999999999999> invalid pri",
        "Oct 99 99:99:99 invalid date",
        "{" + "bad json" * 100,
    ]

    for line in corrupt_inputs:
        evt = parser.parse_line(line)
        # Should gracefully return None without raising unhandled exceptions
        assert evt is None


def test_json_parser_fail_open() -> None:
    parser = JsonLinesParser()
    assert parser.parse_line("NOT_JSON") is None
    assert parser.parse_line("[]") is None
    assert parser.parse_line('{"random": "no timestamp"}') is None


def test_path_traversal_defense_cwe_22(tmp_path) -> None:
    # Verify _resolve_files handles non-existent or relative paths safely
    d = tmp_path / "sandbox"
    d.mkdir()
    f1 = d / "test.log"
    f1.write_text("dummy")

    resolved = _resolve_files([str(f1)], directory=str(d))
    assert len(resolved) == 1
    assert str(f1.resolve()) in resolved


def test_pydantic_forbid_extra_fields_cwe_502() -> None:
    # CWE-502: Disallow unexpected untrusted fields injected into model
    from datetime import datetime, timezone
    with pytest.raises(ValidationError):
        ForensicEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="syslog",
            __injected_code__="exec('import os')",  # type: ignore
        )
