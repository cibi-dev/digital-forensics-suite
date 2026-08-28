"""
Command Line Interface for ISO/IEC 27037 forensic custody management.
Supports: add, verify, proof, audit, cert subcommands.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from custody.certificate import export_certificate_json, generate_certificate, verify_certificate
from custody.evidence import (
    AuditPathStep,
    CustodyCertificateModel,
    EvidenceItem,
    EvidenceMetadata,
    MerkleProofModel,
    VerificationResult,
    utcnow_iso,
)
from custody.hasher import DEFAULT_CHUNK_SIZE, HashAlgorithm, hash_file, validate_safe_path, verify_digest
from custody.merkle import MerkleProof, MerkleTree
from custody.storage import CustodyStorage


def _get_db(db_path: Optional[str]) -> CustodyStorage:
    path = db_path or os.environ.get("CUSTODY_DB", "custody.db")
    return CustodyStorage(path)


def handle_add(args: argparse.Namespace) -> int:
    """Handle 'add' command: registers a new forensic evidence file."""
    try:
        safe_target = validate_safe_path(args.file)
        file_size = safe_target.stat().st_size
        algo = HashAlgorithm.BLAKE3 if "blake3" in args.algo.lower() else HashAlgorithm.SHA256
        
        file_hash = hash_file(safe_target, algorithm=algo)
        
        metadata = EvidenceMetadata(
            source_path=str(safe_target),
            file_size_bytes=file_size,
            custody_officer=args.officer,
            acquisition_timestamp=utcnow_iso(),
            acquisition_method=args.method,
            mime_type=args.mime or "application/octet-stream",
            hardware_device=args.device,
            case_id=args.case,
            notes=args.notes,
        )
        
        item = EvidenceItem(
            algorithm=algo.value,
            hash_value=file_hash,
            metadata=metadata,
        )
        
        with _get_db(args.db) as storage:
            storage.store_evidence(item)
            
        if args.json:
            print(json.dumps(item.model_dump(), indent=2))
        else:
            print(f"[+] Evidence Registered Successfully")
            print(f"    Evidence ID : {item.evidence_id}")
            print(f"    Hash ({algo.value}): {item.hash_value}")
            print(f"    Source Path : {item.metadata.source_path}")
            print(f"    Size (bytes): {item.metadata.file_size_bytes}")
            print(f"    Officer     : {item.metadata.custody_officer}")
            if item.metadata.case_id:
                print(f"    Case ID     : {item.metadata.case_id}")
        return 0
    except Exception as exc:
        print(f"[!] Error registering evidence: {exc}", file=sys.stderr)
        return 1


def handle_verify(args: argparse.Namespace) -> int:
    """Handle 'verify' command: verifies a file against database or expected hash."""
    try:
        safe_target = validate_safe_path(args.file)
        algo = HashAlgorithm.BLAKE3 if "blake3" in args.algo.lower() else HashAlgorithm.SHA256
        computed_hash = hash_file(safe_target, algorithm=algo)
        
        expected_hash = args.expected_hash
        evidence_id = args.evidence_id
        
        if not expected_hash and evidence_id:
            with _get_db(args.db) as storage:
                ev = storage.get_evidence_by_id(evidence_id)
                if ev is None:
                    print(f"[!] Evidence ID not found in database: {evidence_id}", file=sys.stderr)
                    return 1
                expected_hash = ev.hash_value
        elif not expected_hash and not evidence_id:
            with _get_db(args.db) as storage:
                ev = storage.get_evidence_by_hash(computed_hash)
                if ev is not None:
                    expected_hash = ev.hash_value
                    evidence_id = ev.evidence_id
                else:
                    print(f"[!] No match found in database for file hash {computed_hash}", file=sys.stderr)
                    return 1

        is_valid = verify_digest(computed_hash, expected_hash)
        res = VerificationResult(
            is_valid=is_valid,
            evidence_id=evidence_id,
            computed_hash=computed_hash,
            expected_hash=expected_hash,
            message="Evidence hash matched successfully." if is_valid else "Hash mismatch: evidence may be modified.",
        )
        
        if args.json:
            print(json.dumps(res.model_dump(), indent=2))
        else:
            status = "VERIFIED" if is_valid else "TAMPERED / MISMATCH"
            print(f"[{'+' if is_valid else '!'}] Status        : {status}")
            print(f"    File          : {safe_target}")
            print(f"    Computed Hash : {computed_hash}")
            print(f"    Expected Hash : {expected_hash}")
            if evidence_id:
                print(f"    Evidence ID   : {evidence_id}")
        return 0 if is_valid else 1
    except Exception as exc:
        print(f"[!] Error verifying evidence: {exc}", file=sys.stderr)
        return 1


def handle_proof(args: argparse.Namespace) -> int:
    """Handle 'proof' command: generates inclusion proof for an evidence item."""
    try:
        with _get_db(args.db) as storage:
            evidences = storage.list_evidences(case_id=args.case)
            if not evidences:
                print("[!] No evidences found in database.", file=sys.stderr)
                return 1

            target_idx: Optional[int] = None
            if args.evidence_id:
                for idx, ev in enumerate(evidences):
                    if ev.evidence_id == args.evidence_id:
                        target_idx = idx
                        break
            elif args.hash:
                for idx, ev in enumerate(evidences):
                    if ev.hash_value.lower() == args.hash.lower():
                        target_idx = idx
                        break
            else:
                print("[!] Must specify either --evidence-id or --hash", file=sys.stderr)
                return 1

            if target_idx is None:
                print("[!] Target evidence not found in tree set", file=sys.stderr)
                return 1

            leaf_hashes = [e.hash_value for e in evidences]
            tree = MerkleTree(leaf_hashes, algorithm=evidences[0].algorithm, is_prehashed=True)
            proof = tree.get_proof(target_idx)
            is_valid = proof.verify()

            proof_model = MerkleProofModel(
                leaf_index=proof.leaf_index,
                leaf_hash=proof.leaf_hash,
                audit_path=[AuditPathStep(hash=n.hash, position=n.position) for n in proof.audit_path],
                root_hash=proof.root_hash,
                algorithm=proof.algorithm,  # type: ignore[arg-type]
                total_leaves=proof.total_leaves,
            )

            if args.json:
                print(json.dumps(proof_model.model_dump(), indent=2))
            else:
                print(f"[+] Inclusion Proof Generated (Valid: {is_valid})")
                print(f"    Leaf Index   : {proof.leaf_index} / {proof.total_leaves}")
                print(f"    Leaf Hash    : {proof.leaf_hash}")
                print(f"    Root Hash    : {proof.root_hash}")
                print(f"    Audit Steps  : {len(proof.audit_path)}")
                for i, step in enumerate(proof.audit_path):
                    print(f"      Step {i+1}: [{step.position.upper()}] {step.hash}")
            return 0 if is_valid else 1
    except Exception as exc:
        print(f"[!] Error generating proof: {exc}", file=sys.stderr)
        return 1


def handle_audit(args: argparse.Namespace) -> int:
    """Handle 'audit' command: full chain integrity verification across all evidences."""
    try:
        with _get_db(args.db) as storage:
            evidences = storage.list_evidences(case_id=args.case)
            if not evidences:
                print("[+] Storage is empty. Nothing to audit.")
                return 0

            intact_count = 0
            tampered_items: List[dict] = []

            for ev in evidences:
                p = Path(ev.metadata.source_path)
                if not p.exists() or not p.is_file():
                    tampered_items.append({
                        "evidence_id": ev.evidence_id,
                        "error": "File missing or inaccessible",
                        "path": ev.metadata.source_path,
                    })
                    continue

                curr_hash = hash_file(p, algorithm=ev.algorithm)
                if verify_digest(curr_hash, ev.hash_value):
                    intact_count += 1
                else:
                    tampered_items.append({
                        "evidence_id": ev.evidence_id,
                        "path": ev.metadata.source_path,
                        "expected_hash": ev.hash_value,
                        "computed_hash": curr_hash,
                    })

            leaf_hashes = [e.hash_value for e in evidences]
            tree = MerkleTree(leaf_hashes, algorithm=args.algo or evidences[0].algorithm, is_prehashed=True)
            storage.store_merkle_root(
                root_hash=tree.root,
                algorithm=tree.algorithm.value,
                total_leaves=tree.leaf_count,
                case_id=args.case,
            )

            is_clean = len(tampered_items) == 0
            audit_report = {
                "timestamp": utcnow_iso(),
                "case_id": args.case,
                "total_evidences": len(evidences),
                "intact_count": intact_count,
                "tampered_count": len(tampered_items),
                "merkle_root": tree.root,
                "chain_status": "INTEACT" if is_clean else "TAMPER_DETECTED",
                "tampered_details": tampered_items,
            }

            if args.json:
                print(json.dumps(audit_report, indent=2))
            else:
                status_str = "CHAIN INTEGRITY VERIFIED (100% OK)" if is_clean else "CHAIN TAMPER DETECTED"
                print(f"[{'+' if is_clean else '!'}] Audit Result : {status_str}")
                print(f"    Total Evidences : {len(evidences)}")
                print(f"    Intact Items    : {intact_count}")
                print(f"    Tampered Items  : {len(tampered_items)}")
                print(f"    Merkle Root     : {tree.root}")
                if tampered_items:
                    print("\n[!] Tampered Evidence Summary:")
                    for t in tampered_items:
                        print(f"    - ID: {t.get('evidence_id')} | Path: {t.get('path')} | Error: {t.get('error', 'Hash mismatch')}")
            return 0 if is_clean else 1
    except Exception as exc:
        print(f"[!] Error during forensic audit: {exc}", file=sys.stderr)
        return 1


def handle_cert(args: argparse.Namespace) -> int:
    """Handle 'cert' command: generate or verify HMAC-signed non-repudiation certificates."""
    try:
        secret_key = args.key or os.environ.get("CUSTODY_SECRET_KEY")
        if not secret_key:
            print("[!] Secret key is required. Provide --key or set CUSTODY_SECRET_KEY environment variable.", file=sys.stderr)
            return 1

        if args.cert_action == "generate":
            with _get_db(args.db) as storage:
                evidences = storage.list_evidences(case_id=args.case)
                if not evidences:
                    print("[!] Cannot generate certificate: No evidences found in database.", file=sys.stderr)
                    return 1

                leaf_hashes = [e.hash_value for e in evidences]
                tree = MerkleTree(leaf_hashes, algorithm=args.algo or evidences[0].algorithm, is_prehashed=True)
                
                cert = generate_certificate(
                    root_hash=tree.root,
                    evidence_items=evidences,
                    secret_key=secret_key,
                    signer_identity=args.signer or "ForensicAuthority",
                    case_id=args.case,
                    algorithm=tree.algorithm.value,
                )
                storage.store_certificate(cert)
                
                json_output = export_certificate_json(cert)
                if args.out:
                    out_path = Path(args.out).resolve()
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(json_output, encoding="utf-8")
                    print(f"[+] Certificate saved to: {out_path}")
                else:
                    print(json_output)
                return 0

        elif args.cert_action == "verify":
            if not args.cert_file:
                print("[!] Must specify certificate file to verify.", file=sys.stderr)
                return 1
            safe_cert_path = validate_safe_path(args.cert_file)
            cert_content = safe_cert_path.read_text(encoding="utf-8")
            result = verify_certificate(cert_content, secret_key=secret_key)
            
            if args.json:
                print(json.dumps(result.model_dump(), indent=2))
            else:
                status = "VALID SIGNATURE" if result.is_valid else "INVALID / TAMPERED"
                print(f"[{'+' if result.is_valid else '!'}] Certificate Status : {status}")
                print(f"    Certificate ID     : {result.evidence_id}")
                print(f"    Details            : {result.message}")
            return 0 if result.is_valid else 1
        else:
            print(f"[!] Unknown cert action: {args.cert_action}", file=sys.stderr)
            return 1
    except Exception as exc:
        print(f"[!] Error handling certificate: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="custody",
        description="ISO/IEC 27037 Forensic Chain of Custody CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available subcommands")

    # Command: add
    p_add = subparsers.add_parser("add", help="Add and cryptographically register evidence file")
    p_add.add_argument("file", help="Path to evidence file")
    p_add.add_argument("--db", help="Path to SQLite custody database")
    p_add.add_argument("--algo", default="sha256", choices=["sha256", "blake3"], help="Hash algorithm")
    p_add.add_argument("--officer", default="ForensicOfficer-01", help="Custody officer ID")
    p_add.add_argument("--case", help="Forensic case ID")
    p_add.add_argument("--method", default="logical_copy", help="Acquisition method")
    p_add.add_argument("--mime", help="MIME type")
    p_add.add_argument("--device", help="Hardware device SN / Host")
    p_add.add_argument("--notes", help="Investigator notes")
    p_add.add_argument("--json", action="store_true", help="Output JSON format")

    # Command: verify
    p_verify = subparsers.add_parser("verify", help="Verify evidence file against chain or expected hash")
    p_verify.add_argument("file", help="Path to evidence file to verify")
    p_verify.add_argument("--db", help="Path to SQLite custody database")
    p_verify.add_argument("--algo", default="sha256", choices=["sha256", "blake3"], help="Hash algorithm")
    p_verify.add_argument("--expected-hash", help="Explicit expected hash")
    p_verify.add_argument("--evidence-id", help="Evidence ID to lookup in database")
    p_verify.add_argument("--json", action="store_true", help="Output JSON format")

    # Command: proof
    p_proof = subparsers.add_parser("proof", help="Generate inclusion proof for evidence item")
    p_proof.add_argument("--db", help="Path to SQLite custody database")
    p_proof.add_argument("--case", help="Forensic case ID")
    p_proof.add_argument("--evidence-id", help="Target evidence ID")
    p_proof.add_argument("--hash", help="Target evidence hash")
    p_proof.add_argument("--json", action="store_true", help="Output JSON format")

    # Command: audit
    p_audit = subparsers.add_parser("audit", help="Audit all evidences in custody chain for tamper detection")
    p_audit.add_argument("--db", help="Path to SQLite custody database")
    p_audit.add_argument("--case", help="Forensic case ID")
    p_audit.add_argument("--algo", default="sha256", choices=["sha256", "blake3"], help="Tree hash algorithm")
    p_audit.add_argument("--json", action="store_true", help="Output JSON format")

    # Command: cert
    p_cert = subparsers.add_parser("cert", help="Generate or verify signed custody certificates")
    p_cert.add_argument("cert_action", choices=["generate", "verify"], help="Certificate action")
    p_cert.add_argument("cert_file", nargs="?", help="Certificate file path (required for verify)")
    p_cert.add_argument("--db", help="Path to SQLite custody database")
    p_cert.add_argument("--case", help="Forensic case ID")
    p_cert.add_argument("--key", help="HMAC secret key")
    p_cert.add_argument("--signer", default="ForensicAuthority", help="Signer identity")
    p_cert.add_argument("--algo", default="sha256", choices=["sha256", "blake3"], help="Hash algorithm")
    p_cert.add_argument("--out", help="Output file path for generated certificate")
    p_cert.add_argument("--json", action="store_true", help="Output JSON format")

    return parser


def main(argv: Optional[List[str]] = None) -> None:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    handlers = {
        "add": handle_add,
        "verify": handle_verify,
        "proof": handle_proof,
        "audit": handle_audit,
        "cert": handle_cert,
    }

    handler = handlers.get(args.command)
    if handler:
        sys.exit(handler(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
