"""Command-line interface (CLI) for entropy-file-carver forensic suite."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from carver.entropy import calculate_entropy, generate_file_entropy_map
from carver.extractor import Extractor, carve_files_from_mmap
from carver.validator import FileValidator, validate_carved_file


def setup_logging(verbose: bool = False) -> None:
    """Configure standard logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="[%(levelname)s] %(message)s",
        level=level,
    )


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute 'scan' subcommand to identify embedded files without writing to disk."""
    target_path = Path(args.target).resolve()
    if not target_path.is_file():
        print(f"Error: Target file not found: {target_path}", file=sys.stderr)
        return 1

    extractor = Extractor(
        min_size=args.min_size,
        validate_integrity=not args.no_validate,
    )
    result = extractor.carve_file(source_path=target_path, output_dir=None)

    if args.json:
        print(result.model_dump_json(indent=2))
        return 0

    print(f"\n========================================================")
    print(f"  Entropy File Carver - Binary Scan Report")
    print(f"========================================================")
    print(f"Target:      {result.source_file}")
    print(f"Total Size:  {result.total_scanned_bytes:,} bytes")
    print(f"Files Found: {result.files_found}")
    print(f"--------------------------------------------------------")
    print(f"{'Offset':<12} {'End Offset':<12} {'Size (B)':<10} {'Format':<8} {'Entropy':<8} {'Status'}")
    print(f"--------------------------------------------------------")

    for f in result.carved_files:
        status = "VALID" if f.is_valid else "CORRUPT"
        if f.has_stego:
            status += " [STEGO/ENCRYPTED OVERLAY!]"
        print(
            f"0x{f.offset:08X}   0x{f.end_offset:08X}   {f.size:<10,} {f.format_name:<8} {f.entropy:<8.4f} {status}"
        )

    print(f"--------------------------------------------------------\n")
    return 0


def cmd_carve(args: argparse.Namespace) -> int:
    """Execute 'carve' subcommand to extract embedded files safely to output directory."""
    target_path = Path(args.target).resolve()
    if not target_path.is_file():
        print(f"Error: Target file not found: {target_path}", file=sys.stderr)
        return 1

    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    extractor = Extractor(
        min_size=args.min_size,
        max_file_size=args.max_file_size,
        validate_integrity=not args.no_validate,
    )
    result = extractor.carve_file(source_path=target_path, output_dir=output_dir)

    # Save manifest.json in output directory
    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as mf:
        mf.write(result.model_dump_json(indent=2))

    if args.json:
        print(result.model_dump_json(indent=2))
        return 0

    print(f"\n========================================================")
    print(f"  Entropy File Carver - Extraction Complete")
    print(f"========================================================")
    print(f"Source:        {result.source_file}")
    print(f"Output Dir:    {output_dir}")
    print(f"Files Carved:  {result.files_carved} / {result.files_found}")
    print(f"Manifest:      {manifest_path}")
    print(f"--------------------------------------------------------")
    for f in result.carved_files:
        print(f" - [{f.format_name}] {f.output_path} ({f.size:,} bytes, H={f.entropy:.4f})")
    print(f"========================================================\n")
    return 0


def cmd_entropy_map(args: argparse.Namespace) -> int:
    """Execute 'entropy-map' subcommand to visualize Shannon entropy distribution."""
    target_path = Path(args.target).resolve()
    if not target_path.is_file():
        print(f"Error: Target file not found: {target_path}", file=sys.stderr)
        return 1

    emap = generate_file_entropy_map(target_path, block_size=args.block_size)

    if args.json:
        print(emap.model_dump_json(indent=2))
        return 0

    print(emap.to_ascii_graph())
    high_regions = emap.find_high_entropy_regions(threshold=args.high_threshold)
    if high_regions:
        print(f"\n⚠️  High-Entropy Regions Detected (>= {args.high_threshold} bits/byte):")
        for start, end in high_regions:
            print(f"   0x{start:08X} - 0x{end:08X} ({end - start:,} bytes)")
    print()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Execute 'report' subcommand to generate comprehensive forensic audit."""
    target_path = Path(args.target).resolve()
    if not target_path.is_file():
        print(f"Error: Target file not found: {target_path}", file=sys.stderr)
        return 1

    emap = generate_file_entropy_map(target_path, block_size=4096)
    extractor = Extractor(validate_integrity=True)
    extraction = extractor.carve_file(source_path=target_path, output_dir=None)

    report_data: dict[str, Any] = {
        "file": str(target_path),
        "size_bytes": target_path.stat().st_size,
        "entropy_statistics": {
            "mean": emap.mean_entropy,
            "min": emap.min_entropy,
            "max": emap.max_entropy,
            "blocks_count": len(emap.blocks),
        },
        "high_entropy_regions": [
            {"start_offset": hex(s), "end_offset": hex(e), "size": e - s}
            for s, e in emap.find_high_entropy_regions(threshold=7.2)
        ],
        "carved_files": [f.model_dump() for f in extraction.carved_files],
        "steganography_alerts": [
            {
                "offset": hex(f.offset),
                "format": f.format_name,
                "anomaly_score": f.anomaly_score,
                "reason": f.validation_reason,
            }
            for f in extraction.carved_files
            if f.has_stego or f.anomaly_score >= 0.5
        ],
    }

    output_str = ""
    if args.format == "json":
        output_str = json.dumps(report_data, indent=2)
    else:
        # Markdown format
        lines = [
            f"# Forensic Analysis Report: `{target_path.name}`",
            f"",
            f"- **Target Path:** `{target_path}`",
            f"- **Total Size:** `{target_path.stat().st_size:,}` bytes",
            f"- **Mean Entropy:** `{emap.mean_entropy:.4f}` bits/byte (Range: `{emap.min_entropy:.4f}` - `{emap.max_entropy:.4f}`)",
            f"",
            f"## 📦 Embedded Files Detected ({extraction.files_found})",
            f"",
            f"| Offset | End Offset | Size (Bytes) | Format | Entropy | Validation | Stego/Anomaly |",
            f"|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
        ]
        for f in extraction.carved_files:
            lines.append(
                f"| `0x{f.offset:08X}` | `0x{f.end_offset:08X}` | {f.size:,} | {f.format_name} | {f.entropy:.4f} | {'✅ Valid' if f.is_valid else '❌ Corrupt'} | {'⚠️ Alert' if f.has_stego else 'Normal'} |"
            )

        lines.extend([
            f"",
            f"## 🚨 Steganography & Encrypted Overlay Alerts",
            f"",
        ])
        if report_data["steganography_alerts"]:
            for alert in report_data["steganography_alerts"]:
                lines.append(f"- **Offset {alert['offset']} ({alert['format']}):** {alert['reason']} (Score: {alert['anomaly_score']})")
        else:
            lines.append("No hidden steganographic or high-entropy overlay anomalies detected.")

        lines.append("")
        output_str = "\n".join(lines)

    if args.output:
        out_file = Path(args.output).resolve()
        out_file.write_text(output_str, encoding="utf-8")
        print(f"Report saved to: {out_file}")
    else:
        print(output_str)

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="entropy-file-carver",
        description="Enterprise-grade forensic binary scanner & Shannon entropy file carver.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")

    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommand to execute")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan binary file for embedded signatures")
    p_scan.add_argument("target", help="Path to binary file or disk image to scan")
    p_scan.add_argument("--min-size", type=int, default=16, help="Minimum file size in bytes (default: 16)")
    p_scan.add_argument("--no-validate", action="store_true", help="Disable format integrity validation")
    p_scan.add_argument("--json", action="store_true", help="Output results in JSON format")

    # carve
    p_carve = subparsers.add_parser("carve", help="Extract embedded files to output directory")
    p_carve.add_argument("target", help="Path to binary file or disk image")
    p_carve.add_argument("-o", "--output", required=True, help="Target output directory for carved files")
    p_carve.add_argument("--min-size", type=int, default=16, help="Minimum file size in bytes (default: 16)")
    p_carve.add_argument(
        "--max-file-size",
        type=int,
        default=200 * 1024 * 1024,
        help="Maximum carved file size in bytes (default: 200MB)",
    )
    p_carve.add_argument("--no-validate", action="store_true", help="Disable format integrity validation")
    p_carve.add_argument("--json", action="store_true", help="Output results in JSON format")

    # entropy-map
    p_map = subparsers.add_parser("entropy-map", help="Compute and visualize Shannon entropy distribution")
    p_map.add_argument("target", help="Path to binary file")
    p_map.add_argument("-b", "--block-size", type=int, default=4096, help="Block size in bytes (default: 4096)")
    p_map.add_argument(
        "--high-threshold",
        type=float,
        default=7.2,
        help="Entropy threshold to flag high-entropy regions (default: 7.2)",
    )
    p_map.add_argument("--json", action="store_true", help="Output entropy map in JSON format")

    # report
    p_rep = subparsers.add_parser("report", help="Generate comprehensive forensic analysis report")
    p_rep.add_argument("target", help="Path to binary file")
    p_rep.add_argument("-o", "--output", help="Output report file path")
    p_rep.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Report format (default: markdown)"
    )

    return parser


def main(args_list: list[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(args_list)

    setup_logging(args.verbose)

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "carve":
        return cmd_carve(args)
    elif args.command == "entropy-map":
        return cmd_entropy_map(args)
    elif args.command == "report":
        return cmd_report(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
