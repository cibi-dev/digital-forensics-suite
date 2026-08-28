"""
Tests for custody.cli module: command line interface subcommands (add, verify, proof, audit, cert).
"""

import json
from pathlib import Path
import pytest

from custody.cli import main
from custody.hasher import hash_file


def test_cli_add_and_verify(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "custody.db")
    evidence_file = tmp_path / "evidence_1.txt"
    evidence_file.write_text("Forensic sample evidence content")

    # 1. Add evidence
    with pytest.raises(SystemExit) as exc_info:
        main([
            "add", str(evidence_file),
            "--db", db_path,
            "--officer", "Detective-01",
            "--case", "CASE-99",
            "--mime", "text/plain",
            "--device", "Workstation-A",
            "--notes", "Initial drive dump",
        ])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "Evidence Registered Successfully" in out
    assert "CASE-99" in out

    # 2. Verify evidence automatically (hash lookup in db)
    with pytest.raises(SystemExit) as exc_info:
        main(["verify", str(evidence_file), "--db", db_path])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out


def test_cli_add_json_output(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "custody.db")
    evidence_file = tmp_path / "evidence_json.txt"
    evidence_file.write_text("JSON output test")

    with pytest.raises(SystemExit) as exc_info:
        main(["add", str(evidence_file), "--db", db_path, "--json"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert "evidence_id" in parsed
    assert "hash_value" in parsed


def test_cli_add_invalid_file(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "custody.db")
    missing_file = tmp_path / "nonexistent.bin"

    with pytest.raises(SystemExit) as exc_info:
        main(["add", str(missing_file), "--db", db_path])
    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "Error registering evidence" in err


def test_cli_verify_with_evidence_id(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "custody.db")
    evidence_file = tmp_path / "evidence_id_test.txt"
    evidence_file.write_text("ID lookup content")

    # Add evidence and get its ID from JSON
    with pytest.raises(SystemExit):
        main(["add", str(evidence_file), "--db", db_path, "--json"])
    out = capsys.readouterr().out
    ev_id = json.loads(out)["evidence_id"]

    # Verify using --evidence-id
    with pytest.raises(SystemExit) as exc_info:
        main(["verify", str(evidence_file), "--db", db_path, "--evidence-id", ev_id, "--json"])
    assert exc_info.value.code == 0
    out_ver = capsys.readouterr().out
    ver_data = json.loads(out_ver)
    assert ver_data["is_valid"] is True
    assert ver_data["evidence_id"] == ev_id

    # Verify with non-existent evidence-id
    with pytest.raises(SystemExit) as exc_info:
        main(["verify", str(evidence_file), "--db", db_path, "--evidence-id", "NON-EXISTENT-ID"])
    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "Evidence ID not found" in err


def test_cli_verify_unknown_file_not_in_db(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "custody.db")
    evidence_file = tmp_path / "untracked.bin"
    evidence_file.write_text("untracked payload")

    with pytest.raises(SystemExit) as exc_info:
        main(["verify", str(evidence_file), "--db", db_path])
    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "No match found in database" in err


def test_cli_verify_tampered_file(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "custody.db")
    evidence_file = tmp_path / "evidence_tamper.txt"
    evidence_file.write_text("Original content")

    # Add evidence
    with pytest.raises(SystemExit):
        main(["add", str(evidence_file), "--db", db_path])
    capsys.readouterr()

    # Modify file content on disk (Tampering)
    evidence_file.write_text("Tampered modified content")

    # Verify should fail
    with pytest.raises(SystemExit) as exc_info:
        main(["verify", str(evidence_file), "--db", db_path])
    assert exc_info.value.code == 1


def test_cli_verify_with_explicit_hash(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    evidence_file = tmp_path / "evidence_explicit.txt"
    evidence_file.write_text("Explicit hash testing")
    correct_hash = hash_file(evidence_file, algorithm="sha256")

    # Verify with --expected-hash
    with pytest.raises(SystemExit) as exc_info:
        main(["verify", str(evidence_file), "--expected-hash", correct_hash])
    assert exc_info.value.code == 0

    # Verify with bad --expected-hash
    with pytest.raises(SystemExit) as exc_info:
        main(["verify", str(evidence_file), "--expected-hash", "0" * 64])
    assert exc_info.value.code == 1


def test_cli_proof_generation(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "custody.db")
    f1 = tmp_path / "f1.bin"
    f2 = tmp_path / "f2.bin"
    f1.write_text("file 1")
    f2.write_text("file 2")

    # Register f1 and f2
    with pytest.raises(SystemExit):
        main(["add", str(f1), "--db", db_path, "--case", "C1", "--json"])
    out1 = capsys.readouterr().out
    ev1_id = json.loads(out1)["evidence_id"]

    with pytest.raises(SystemExit):
        main(["add", str(f2), "--db", db_path, "--case", "C1"])
    capsys.readouterr()

    # Generate proof by ID
    with pytest.raises(SystemExit) as exc_info:
        main(["proof", "--db", db_path, "--case", "C1", "--evidence-id", ev1_id])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "Inclusion Proof Generated" in out

    f1_hash = hash_file(f1, algorithm="sha256")

    # Generate proof by hash and json
    with pytest.raises(SystemExit) as exc_info:
        main(["proof", "--db", db_path, "--case", "C1", "--hash", f1_hash, "--json"])
    assert exc_info.value.code == 0
    out_json = capsys.readouterr().out
    proof_data = json.loads(out_json)
    assert proof_data["leaf_index"] == 0
    assert "audit_path" in proof_data


def test_cli_proof_errors(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "custody.db")

    # Empty DB
    with pytest.raises(SystemExit) as exc_info:
        main(["proof", "--db", db_path, "--hash", "0"*64])
    assert exc_info.value.code == 1

    # Missing flags
    evidence_file = tmp_path / "ev.bin"
    evidence_file.write_text("test")
    with pytest.raises(SystemExit):
        main(["add", str(evidence_file), "--db", db_path])
    capsys.readouterr()

    with pytest.raises(SystemExit) as exc_info:
        main(["proof", "--db", db_path])
    assert exc_info.value.code == 1

    # Target evidence not found in tree
    with pytest.raises(SystemExit) as exc_info:
        main(["proof", "--db", db_path, "--hash", "f"*64])
    assert exc_info.value.code == 1


def test_cli_audit_command(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "custody.db")
    f1 = tmp_path / "audit_1.txt"
    f2 = tmp_path / "audit_2.txt"
    f1.write_text("clean evidence 1")
    f2.write_text("clean evidence 2")

    with pytest.raises(SystemExit):
        main(["add", str(f1), "--db", db_path])
    with pytest.raises(SystemExit):
        main(["add", str(f2), "--db", db_path])
    capsys.readouterr()

    # 1. Audit clean chain
    with pytest.raises(SystemExit) as exc_info:
        main(["audit", "--db", db_path])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "CHAIN INTEGRITY VERIFIED" in out

    # 2. Tamper one file on disk
    f2.write_text("corrupted content on disk")
    with pytest.raises(SystemExit) as exc_info:
        main(["audit", "--db", db_path])
    assert exc_info.value.code == 1
    out_tampered = capsys.readouterr().out
    assert "CHAIN TAMPER DETECTED" in out_tampered

    # 3. Delete one file completely
    f1.unlink()
    with pytest.raises(SystemExit) as exc_info:
        main(["audit", "--db", db_path, "--json"])
    assert exc_info.value.code == 1
    out_json = capsys.readouterr().out
    report = json.loads(out_json)
    assert report["tampered_count"] >= 1


def test_cli_audit_empty_db(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "empty_custody.db")
    with pytest.raises(SystemExit) as exc_info:
        main(["audit", "--db", db_path])
    assert exc_info.value.code == 0


def test_cli_cert_generate_and_verify(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "custody.db")
    cert_file = tmp_path / "case_certificate.json"
    evidence_file = tmp_path / "cert_ev.txt"
    evidence_file.write_text("Certified evidence content")

    secret_key = "mock_secret_key_123"

    with pytest.raises(SystemExit):
        main(["add", str(evidence_file), "--db", db_path, "--algo", "blake3"])
    capsys.readouterr()

    # 1. Generate certificate and save to stdout
    with pytest.raises(SystemExit) as exc_info:
        main([
            "cert", "generate",
            "--db", db_path,
            "--key", secret_key,
            "--signer", "ForensicAuthority-Lead",
            "--algo", "blake3",
        ])
    assert exc_info.value.code == 0
    stdout_cert = capsys.readouterr().out
    assert "CERT-" in stdout_cert

    # 2. Generate certificate and save to file with --out
    with pytest.raises(SystemExit) as exc_info:
        main([
            "cert", "generate",
            "--db", db_path,
            "--key", secret_key,
            "--signer", "ForensicAuthority-Lead",
            "--out", str(cert_file),
        ])
    assert exc_info.value.code == 0
    assert cert_file.exists()

    # 3. Verify certificate from file (human output)
    with pytest.raises(SystemExit) as exc_info:
        main([
            "cert", "verify", str(cert_file),
            "--key", secret_key,
        ])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "VALID SIGNATURE" in out

    # 4. Verify certificate from file with --json
    with pytest.raises(SystemExit) as exc_info:
        main([
            "cert", "verify", str(cert_file),
            "--key", secret_key,
            "--json",
        ])
    assert exc_info.value.code == 0
    out_json = capsys.readouterr().out
    ver_res = json.loads(out_json)
    assert ver_res["is_valid"] is True

    # 5. Verify with wrong key
    with pytest.raises(SystemExit) as exc_info:
        main([
            "cert", "verify", str(cert_file),
            "--key", "mock_wrong_key_999",
        ])
    assert exc_info.value.code == 1


def test_cli_cert_errors(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    db_path = str(tmp_path / "empty_cert_db.db")

    # Missing key
    with pytest.raises(SystemExit) as exc_info:
        main(["cert", "generate", "--db", db_path])
    assert exc_info.value.code == 1
    assert "Secret key is required" in capsys.readouterr().err

    # Empty DB generate
    with pytest.raises(SystemExit) as exc_info:
        main(["cert", "generate", "--db", db_path, "--key", "mock_secret_key_123"])
    assert exc_info.value.code == 1
    assert "No evidences found" in capsys.readouterr().err

    # Verify without cert_file
    with pytest.raises(SystemExit) as exc_info:
        main(["cert", "verify", "--key", "mock_secret_key_123"])
    assert exc_info.value.code == 1
    assert "Must specify certificate file" in capsys.readouterr().err
