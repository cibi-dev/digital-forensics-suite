"""Executive forensic markdown report exporter."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any, Dict, Iterable, List, Optional, Union

from timeline.integrity import IntegrityAnomaly
from timeline.normalizer import ForensicEvent


def render_markdown_report(
    events: list[ForensicEvent],
    anomalies: Optional[list[IntegrityAnomaly]] = None,
    attack_chains: Optional[list[dict[str, Any]]] = None,
    title: str = "Forensic Timeline & Incident Investigation Report",
    max_timeline_rows: int = 500,
) -> str:
    """Render a comprehensive GitHub Flavored Markdown report from events and analysis findings."""
    anomalies = anomalies or []
    attack_chains = attack_chains or []

    # Calculate statistics
    total_events = len(events)
    sources = sorted(list({e.source_file for e in events}))
    source_types = sorted(list({e.source_type for e in events}))
    start_time_str = events[0].timestamp.isoformat() if events else "N/A"
    end_time_str = events[-1].timestamp.isoformat() if events else "N/A"
    tamper_status = "🔴 COMPROMISED / ANOMALIES DETECTED" if anomalies else "🟢 CLEAN / NO ANOMALIES"

    lines: list[str] = []
    lines.append(f"# 🛡️ {title}")
    lines.append("")
    lines.append(f"> **Report Generated (UTC):** `{datetime.now(timezone.utc).isoformat()}`  ")
    lines.append(f"> **IR Investigation Engine:** `forensic-timeline-reconstructor v0.1.0`")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 📊 1. Executive Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| **Total Forensic Events Processed** | `{total_events:,}` |")
    lines.append(f"| **Timeline Time Window (UTC)** | `{start_time_str}` $\\to$ `{end_time_str}` |")
    lines.append(f"| **Distinct Log Files Analyzed** | `{len(sources)}` ({', '.join(sources) if len(sources) <= 5 else f'{len(sources)} files'}) |")
    lines.append(f"| **Source Types Ingested** | `{', '.join(source_types)}` |")
    lines.append(f"| **Timeline Integrity Status** | **{tamper_status}** |")
    lines.append(f"| **Integrity / Timestomping Anomalies** | `{len(anomalies)}` |")
    lines.append(f"| **Correlated Attack Chains** | `{len(attack_chains)}` |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 2. Integrity & Timestomping Findings
    lines.append("## ⚠️ 2. Timestomping & Integrity Findings")
    lines.append("")
    if not anomalies:
        lines.append("✅ **No timestomping, negative clock jumps, or anomalous deletion gaps detected.** All log streams exhibit monotonically increasing timestamps.")
    else:
        lines.append("| ID | Anomaly Type | Severity | Source File | Line(s) | Delta (s) | Description |")
        lines.append("|---|---|:---:|---|:---:|:---:|---|")
        for a in anomalies:
            lines.append(
                f"| `{a.anomaly_id}` | `{a.anomaly_type}` | **{a.severity}** | `{a.source_file}` | {a.start_line}-{a.end_line} | `{a.delta_seconds:+.3f}s` | {a.description} |"
            )
    lines.append("")
    lines.append("---")
    lines.append("")

    # 3. Correlated Attack Chains
    lines.append("## 🔗 3. Correlated Multi-Stage Incidents")
    lines.append("")
    if not attack_chains:
        lines.append("ℹ️ *No multi-stage attack chains identified based on current correlation rules.*")
    else:
        for idx, chain in enumerate(attack_chains, start=1):
            lines.append(f"### Incident Chain #{idx}: {chain['chain_type']} ({chain['pivot']})")
            lines.append(f"- **Severity:** `{chain['severity']}`")
            lines.append(f"- **Time Range:** `{chain['start_time']}` $\\to$ `{chain['end_time']}`")
            lines.append(f"- **Summary:** {chain['description']}")
            lines.append("")
            lines.append("#### Sequence of Key Events:")
            lines.append("")
            lines.append("| Timestamp (UTC) | Source | Action | User | IP | Message |")
            lines.append("|---|---|---|---|---|---|")
            for e_dict in chain.get("events", []):
                lines.append(
                    f"| `{e_dict.get('timestamp')}` | `{e_dict.get('source_type')}` | `{e_dict.get('action') or '-'}` | `{e_dict.get('user') or '-'}` | `{e_dict.get('client_ip') or '-'}` | {e_dict.get('message') or '-'} |"
                )
            lines.append("")
    lines.append("---")
    lines.append("")

    # 4. Canonical Timeline
    lines.append("## 🕒 4. Canonical Chronological Timeline (UTC Microseconds)")
    lines.append("")
    lines.append(f"> Showing first {min(total_events, max_timeline_rows)} of {total_events} canonical events.")
    lines.append("")
    lines.append("| Timestamp (UTC) | Severity | Source | Host / IP | User | Action | Event Details |")
    lines.append("|---|:---:|---|---|---|---|---|")

    for evt in events[:max_timeline_rows]:
        host_or_ip = evt.client_ip or evt.host or "-"
        user_str = evt.user or "-"
        action_str = evt.action or "-"
        clean_msg = evt.message.replace("|", "\\|").replace("\n", " ")[:120]
        lines.append(
            f"| `{evt.timestamp.isoformat()}` | **{evt.severity}** | `{evt.source_type}` | `{host_or_ip}` | `{user_str}` | `{action_str}` | {clean_msg} |"
        )

    if total_events > max_timeline_rows:
        lines.append("")
        lines.append(f"*... {total_events - max_timeline_rows} additional events truncated for report brevity. Use JSONL export for full event stream.*")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 📋 5. Actionable Incident Response Recommendations")
    lines.append("")
    if anomalies:
        lines.append("1. **Preserve Volatile Artifacts:** Secure disk images and memory captures immediately; timestamps in affected log files indicate clock tampering or deliberate evasion.")
        lines.append("2. **Isolate Compromised Endpoints:** Systems associated with negative clock jumps should be quarantined from the network.")
    if attack_chains:
        lines.append("3. **Revoke Compromised Credentials:** Immediately reset credentials for all users identified in brute-force or privilege escalation chains.")
        lines.append("4. **Block Malicious Source IPs:** Apply perimeter firewall and WAF blocks for high-frequency offending IPs.")
    lines.append("5. **Verify Centralized SIEM/NTP Sync:** Ensure all infrastructure nodes enforce authenticated NTP (chrony/ntpd) with tamper-resistant log forwarding (RFC 5424 over TLS).")
    lines.append("")

    return "\n".join(lines)


def export_markdown_report(
    events: Iterable[ForensicEvent],
    output_file: Optional[str] = None,
    anomalies: Optional[list[IntegrityAnomaly]] = None,
    attack_chains: Optional[list[dict[str, Any]]] = None,
    title: str = "Forensic Timeline & Incident Investigation Report",
    max_timeline_rows: int = 500,
) -> str:
    """Export or write markdown report."""
    event_list = list(events)
    content = render_markdown_report(
        events=event_list,
        anomalies=anomalies,
        attack_chains=attack_chains,
        title=title,
        max_timeline_rows=max_timeline_rows,
    )
    if output_file:
        safe_path = os.path.realpath(output_file)
        os.makedirs(os.path.dirname(safe_path), exist_ok=True)
        with open(safe_path, "w", encoding="utf-8") as f:
            f.write(content)
    return content
