"""Tests for CLI subcommands: parse, correlate, detect-tamper, export."""

import os
import tempfile
import pytest

from timeline.cli import main


@pytest.fixture
def sample_logs(tmp_path):
    syslog_f = tmp_path / "syslog.log"
    syslog_f.write_text(
        "<165>1 2023-10-11T10:00:00.000Z host app 100 ID47 - System boot\n"
        "<165>1 2023-10-11T10:00:05.000Z host app 100 ID47 - Service started\n"
    )

    auth_f = tmp_path / "auth.log"
    auth_f.write_text(
        "Oct 11 10:00:02 host sshd[200]: Accepted publickey for admin from 10.0.0.1 port 50000 ssh2\n"
        "Oct 11 10:00:08 host sudo:   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/ls\n"
    )

    tampered_f = tmp_path / "tampered.log"
    tampered_f.write_text(
        "<165>1 2023-10-11T10:00:00.000Z host app 100 ID47 - Entry 1\n"
        "<165>1 2023-10-11T09:55:00.000Z host app 100 ID47 - Backdated Entry 2\n"
    )

    return {
        "syslog": str(syslog_f),
        "auth": str(auth_f),
        "tampered": str(tampered_f),
        "dir": str(tmp_path),
    }


def test_cli_parse_summary(sample_logs, capsys) -> None:
    code = main(["parse", sample_logs["syslog"], "--format", "summary"])
    assert code == 0
    captured = capsys.readouterr()
    assert "Total events: 2" in captured.out
    assert "SyslogParser" in captured.out


def test_cli_parse_jsonl(sample_logs, tmp_path) -> None:
    out_jsonl = tmp_path / "parsed.jsonl"
    code = main(["parse", sample_logs["syslog"], "--format", "jsonl", "-o", str(out_jsonl)])
    assert code == 0
    assert out_jsonl.exists()
    lines = out_jsonl.read_text().strip().split("\n")
    assert len(lines) == 2


def test_cli_correlate(sample_logs, tmp_path) -> None:
    out_corr = tmp_path / "correlated.jsonl"
    code = main([
        "correlate",
        "--files", sample_logs["syslog"], sample_logs["auth"],
        "--format", "jsonl",
        "-o", str(out_corr),
    ])
    assert code == 0
    assert out_corr.exists()
    lines = out_corr.read_text().strip().split("\n")
    assert len(lines) == 4


def test_cli_correlate_directory(sample_logs, tmp_path) -> None:
    out_md = tmp_path / "report.md"
    code = main([
        "correlate",
        "--dir", sample_logs["dir"],
        "--format", "markdown",
        "-o", str(out_md),
    ])
    assert code == 0
    assert out_md.exists()
    assert "# 🛡️ Correlated Multi-Source Timeline" in out_md.read_text()


def test_cli_detect_tamper_clean(sample_logs) -> None:
    code = main(["detect-tamper", "--files", sample_logs["syslog"]])
    assert code == 0


def test_cli_detect_tamper_compromised(sample_logs, tmp_path) -> None:
    out_json = tmp_path / "tamper_report.json"
    code = main([
        "detect-tamper",
        "--files", sample_logs["tampered"],
        "--format", "json",
        "-o", str(out_json),
    ])
    assert code == 1
    assert out_json.exists()
    content = out_json.read_text()
    assert "NEGATIVE_CLOCK_JUMP" in content


def test_cli_export_full(sample_logs, tmp_path) -> None:
    out_md = tmp_path / "full_report.md"
    code = main([
        "export",
        "--files", sample_logs["syslog"], sample_logs["auth"],
        "--format", "markdown",
        "-o", str(out_md),
        "--detect-chains",
        "--report-title", "Enterprise IR Report",
    ])
    assert code == 0
    assert out_md.exists()
    text = out_md.read_text()
    assert "Enterprise IR Report" in text
    assert "Correlated Multi-Stage Incidents" in text


def test_cli_correlate_stdout(sample_logs, capsys) -> None:
    code = main([
        "correlate",
        "--files", sample_logs["syslog"],
        "--format", "jsonl",
    ])
    assert code == 0
    captured = capsys.readouterr()
    assert '"source_type": "syslog"' in captured.out


def test_cli_detect_tamper_json_stdout(sample_logs, capsys) -> None:
    code = main([
        "detect-tamper",
        "--files", sample_logs["syslog"],
        "--format", "json",
    ])
    assert code == 0
    captured = capsys.readouterr()
    assert '"status": "CLEAN"' in captured.out


def test_cli_error_handling(sample_logs) -> None:
    # Non existent file for parse
    assert main(["parse", "/nonexistent/file/path.log"]) == 1
    # No files provided for correlate
    assert main(["correlate", "--files", "/nonexistent/file.log"]) == 1
    assert main(["detect-tamper", "--files", "/nonexistent/file.log"]) == 1
    assert main(["export", "--files", "/nonexistent/file.log", "--output", "out.md"]) == 1
