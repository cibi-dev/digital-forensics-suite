"""Command Line Interface (CLI) for Forensic Timeline Reconstructor."""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import sys
from typing import List, Optional

from timeline.correlator import TimelineCorrelator, detect_parser_for_file
from timeline.exporters.jsonl import export_jsonl
from timeline.exporters.markdown import export_markdown_report
from timeline.integrity import IntegrityAnalyzer


def _resolve_files(files: Optional[list[str]], directory: Optional[str]) -> list[str]:
    """Safely resolve list of files from explicit file list or directory (CWE-22 defense)."""
    resolved: list[str] = []
    if files:
        for f in files:
            p = os.path.realpath(f)
            if os.path.isfile(p):
                resolved.append(p)
            else:
                sys.stderr.write(f"Warning: File not found: {f}\n")

    if directory:
        dir_real = os.path.realpath(directory)
        if os.path.isdir(dir_real):
            for entry in sorted(os.listdir(dir_real)):
                full_p = os.path.realpath(os.path.join(dir_real, entry))
                # Ensure path stays within directory (CWE-22)
                if os.path.commonpath([dir_real, full_p]) == dir_real and os.path.isfile(full_p):
                    resolved.append(full_p)
        else:
            sys.stderr.write(f"Warning: Directory not found: {directory}\n")

    return list(dict.fromkeys(resolved))


def handle_parse(args: argparse.Namespace) -> int:
    """Handle the 'parse' subcommand."""
    filepath = os.path.realpath(args.file)
    if not os.path.isfile(filepath):
        sys.stderr.write(f"Error: File not found: {args.file}\n")
        return 1

    parser = detect_parser_for_file(filepath)
    events = parser.parse_file(filepath)

    if args.format == "jsonl":
        count = export_jsonl(events, target=args.output or sys.stdout)
        if args.output:
            print(f"Exported {count:,} events to {args.output}")
    else:
        # Summary
        count = 0
        severities: dict[str, int] = {}
        for evt in events:
            count += 1
            severities[evt.severity] = severities.get(evt.severity, 0) + 1
        print(f"File: {filepath}")
        print(f"Parser: {parser.__class__.__name__}")
        print(f"Total events: {count:,}")
        print(f"Severities breakdown: {severities}")

    return 0


def handle_correlate(args: argparse.Namespace) -> int:
    """Handle the 'correlate' subcommand."""
    files = _resolve_files(args.files, args.dir)
    if not files:
        sys.stderr.write("Error: No valid input log files specified.\n")
        return 1

    correlator = TimelineCorrelator()
    merged_stream = correlator.merge_files(files)

    filtered_stream = correlator.filter_events(
        merged_stream,
        start_time=args.start,
        end_time=args.end,
        min_severity=args.min_severity,
        search_pattern=args.search,
    )

    if args.format == "jsonl":
        count = export_jsonl(filtered_stream, target=args.output or sys.stdout)
        if args.output:
            print(f"Correlated and exported {count:,} events to {args.output}")
    elif args.format == "markdown":
        events_list = list(filtered_stream)
        export_markdown_report(
            events_list,
            output_file=args.output,
            title="Correlated Multi-Source Timeline",
        )
        if args.output:
            print(f"Markdown timeline report written to {args.output}")
        else:
            print(export_markdown_report(events_list))

    return 0


def handle_detect_tamper(args: argparse.Namespace) -> int:
    """Handle the 'detect-tamper' subcommand."""
    files = _resolve_files(args.files, args.dir)
    if not files:
        sys.stderr.write("Error: No valid input log files specified.\n")
        return 1

    analyzer = IntegrityAnalyzer(max_allowed_gap_seconds=args.max_gap)
    anomalies = analyzer.analyze_multi_file(files)
    summary = analyzer.generate_integrity_summary(anomalies)

    if args.format == "json":
        output_data = {
            "summary": summary,
            "anomalies": [a.to_dict() for a in anomalies],
        }
        json_str = json.dumps(output_data, indent=2)
        if args.output:
            with open(os.path.realpath(args.output), "w", encoding="utf-8") as f:
                f.write(json_str)
            print(f"Tampering analysis written to {args.output}")
        else:
            print(json_str)
    else:
        print(f"=== TIMELINE INTEGRITY AUDIT ===")
        print(f"Status: {summary['status']}")
        print(f"Files Analyzed: {len(files)}")
        print(f"Total Anomalies: {summary['total_anomalies']}")
        print(f"By Severity: {summary['by_severity']}")
        print(f"By Type: {summary['by_type']}")
        if anomalies:
            print("\nAnomalies Detail:")
            for a in anomalies:
                print(f"  [{a.severity}] {a.anomaly_type} in {a.source_file}:{a.start_line}-{a.end_line}: {a.description}")

    return 1 if anomalies else 0


def handle_export(args: argparse.Namespace) -> int:
    """Handle the 'export' subcommand."""
    files = _resolve_files(args.files, args.dir)
    if not files:
        sys.stderr.write("Error: No valid input log files specified.\n")
        return 1

    correlator = TimelineCorrelator()
    merged_stream = correlator.merge_files(files)

    if args.format == "jsonl":
        count = export_jsonl(merged_stream, target=args.output)
        print(f"Exported {count:,} canonical events to {args.output}")
    elif args.format == "markdown":
        events_list = list(merged_stream)
        analyzer = IntegrityAnalyzer()
        anomalies = analyzer.analyze_multi_file(files)
        attack_chains = correlator.find_attack_chains(events_list) if args.detect_chains else []

        export_markdown_report(
            events_list,
            output_file=args.output,
            anomalies=anomalies,
            attack_chains=attack_chains,
            title=args.report_title or "Forensic Timeline & Incident Investigation Report",
        )
        print(f"Exported executive forensic report to {args.output}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build command-line arguments parser."""
    parser = argparse.ArgumentParser(
        prog="forensic-timeline",
        description="Enterprise IR forensic timeline correlation & timestomping detection engine.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: parse
    p_parse = subparsers.add_parser("parse", help="Parse a single log file into canonical events")
    p_parse.add_argument("file", help="Path to log file")
    p_parse.add_argument("--format", choices=["jsonl", "summary"], default="jsonl", help="Output format")
    p_parse.add_argument("--output", "-o", help="Output destination file (default: stdout)")

    # Subcommand: correlate
    p_corr = subparsers.add_parser("correlate", help="Correlate and merge multiple log files")
    p_corr.add_argument("--files", "-f", nargs="+", help="Log files to correlate")
    p_corr.add_argument("--dir", "-d", help="Directory containing log files")
    p_corr.add_argument("--start", help="Start timestamp filter (ISO/UTC)")
    p_corr.add_argument("--end", help="End timestamp filter (ISO/UTC)")
    p_corr.add_argument("--min-severity", help="Minimum severity threshold (e.g. WARNING, ERROR)")
    p_corr.add_argument("--search", "-s", help="Regex search term")
    p_corr.add_argument("--format", choices=["jsonl", "markdown"], default="jsonl", help="Output format")
    p_corr.add_argument("--output", "-o", help="Output destination file")

    # Subcommand: detect-tamper
    p_tamper = subparsers.add_parser("detect-tamper", help="Detect timestomping, negative clock jumps, and gaps")
    p_tamper.add_argument("--files", "-f", nargs="+", help="Log files to analyze")
    p_tamper.add_argument("--dir", "-d", help="Directory containing log files")
    p_tamper.add_argument("--max-gap", type=float, default=3600.0, help="Max inactivity gap threshold in seconds")
    p_tamper.add_argument("--format", choices=["table", "json"], default="table", help="Report format")
    p_tamper.add_argument("--output", "-o", help="Output destination file")

    # Subcommand: export
    p_exp = subparsers.add_parser("export", help="Export canonical timeline and investigation report")
    p_exp.add_argument("--files", "-f", nargs="+", help="Log files to process")
    p_exp.add_argument("--dir", "-d", help="Directory containing log files")
    p_exp.add_argument("--format", choices=["jsonl", "markdown"], default="markdown", help="Export format")
    p_exp.add_argument("--output", "-o", required=True, help="Output destination file")
    p_exp.add_argument("--report-title", help="Custom markdown report title")
    p_exp.add_argument("--detect-chains", action="store_true", help="Include correlated attack chains in report")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point for CLI execution."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "parse":
        return handle_parse(args)
    elif args.command == "correlate":
        return handle_correlate(args)
    elif args.command == "detect-tamper":
        return handle_detect_tamper(args)
    elif args.command == "export":
        return handle_export(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
