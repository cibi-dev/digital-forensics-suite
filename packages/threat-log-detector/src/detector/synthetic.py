"""Reproducible synthetic log dataset generator for normal and attack scenarios."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field

from detector.parser import EventType, LogEvent, SourceType


NORMAL_USERS = ["juan", "cibi", "developer", "sysadmin", "deployer", "monitoring"]
NORMAL_IPS = [
    "192.168.1.10", "192.168.1.25", "192.168.1.50", "192.168.1.100",
    "10.0.1.15", "10.0.2.30", "172.16.10.5", "198.51.100.15"
]
SPRAY_TARGET_USERS = [
    "root", "admin", "administrator", "test", "guest", "oracle", "postgres",
    "mysql", "ftpuser", "backup", "jenkins", "gitlab", "ansible", "docker",
    "ubuntu", "centos", "support", "sales", "operator", "daemon", "service",
    "nagios", "zabbix", "grafana", "kibana", "elastic", "api", "staging"
]


class DatasetConfig(BaseModel):
    """Configuration for reproducible synthetic dataset generation."""
    model_config = ConfigDict(frozen=True)

    n_normal_events: int = 4000
    n_brute_force_events: int = 500
    n_password_spray_events: int = 300
    n_exfiltration_events: int = 200
    random_seed: int = 42
    start_time: datetime = Field(
        default_factory=lambda: datetime(2026, 8, 27, 10, 0, 0, tzinfo=timezone.utc)
    )


class SyntheticDataset(BaseModel):
    """Container for generated events, raw logs, and ground truth labels."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    events: List[LogEvent]
    raw_logs: List[str]
    labels: List[int]  # 0 = normal, 1 = anomaly/attack
    attack_types: List[str]

    def to_file_bundle(self, base_path: Union[str, Path]) -> Dict[str, str]:
        """Save dataset logs and ground truth labels to disk."""
        dir_path = Path(base_path)
        dir_path.mkdir(parents=True, exist_ok=True)

        log_path = dir_path / "events.log"
        gt_path = dir_path / "ground_truth.json"

        with open(log_path, "w", encoding="utf-8") as f:
            for raw in self.raw_logs:
                f.write(raw + "\n")

        gt_data = {
            "total_events": len(self.labels),
            "normal_count": self.labels.count(0),
            "anomaly_count": self.labels.count(1),
            "labels": self.labels,
            "attack_types": self.attack_types,
        }
        with open(gt_path, "w", encoding="utf-8") as f:
            json.dump(gt_data, f, indent=2)

        return {"logs": str(log_path), "ground_truth": str(gt_path)}


class SyntheticLogGenerator:
    """Deterministic synthetic dataset generator with labeled attack patterns."""

    def __init__(self, config: Optional[DatasetConfig] = None) -> None:
        self.config = config or DatasetConfig()
        self._rng = random.Random(self.config.random_seed)

    def generate(self) -> SyntheticDataset:
        """Generate full mixed dataset of normal activity and attack bursts."""
        self._rng = random.Random(self.config.random_seed)
        
        events: List[LogEvent] = []
        raw_logs: List[str] = []
        labels: List[int] = []
        attack_types: List[str] = []

        curr_time = self.config.start_time

        # 1. Generate Normal Background Activity
        for _ in range(self.config.n_normal_events):
            curr_time += timedelta(seconds=self._rng.uniform(0.5, 4.0))
            ev, raw = self._generate_normal_event(curr_time)
            events.append(ev)
            raw_logs.append(raw)
            labels.append(0)
            attack_types.append("normal")

        # 2. Generate SSH Brute Force Attack
        bf_ip = "198.51.100.42"
        bf_port = self._rng.randint(30000, 60000)
        curr_time += timedelta(seconds=10.0)
        for _ in range(self.config.n_brute_force_events):
            curr_time += timedelta(seconds=self._rng.uniform(0.02, 0.15))
            user = self._rng.choice(["root", "admin", "sysadmin"])
            ev, raw = self._generate_ssh_fail_event(curr_time, bf_ip, bf_port, user, is_anomaly=True)
            events.append(ev)
            raw_logs.append(raw)
            labels.append(1)
            attack_types.append("ssh_brute_force")

        # 3. Generate Password Spraying Attack
        spray_ip = "203.0.113.88"
        spray_port = self._rng.randint(30000, 60000)
        curr_time += timedelta(seconds=15.0)
        for i in range(self.config.n_password_spray_events):
            curr_time += timedelta(seconds=self._rng.uniform(0.5, 2.0))
            user = SPRAY_TARGET_USERS[i % len(SPRAY_TARGET_USERS)]
            ev, raw = self._generate_ssh_fail_event(curr_time, spray_ip, spray_port, user, is_anomaly=True)
            events.append(ev)
            raw_logs.append(raw)
            labels.append(1)
            attack_types.append("password_spray")

        # 4. Generate Data Exfiltration Network Flows
        exfil_src = "10.0.4.15"
        exfil_dst = "185.220.101.5"
        curr_time += timedelta(seconds=10.0)
        for _ in range(self.config.n_exfiltration_events):
            curr_time += timedelta(seconds=self._rng.uniform(0.2, 1.5))
            ev, raw = self._generate_exfiltration_event(curr_time, exfil_src, exfil_dst, is_anomaly=True)
            events.append(ev)
            raw_logs.append(raw)
            labels.append(1)
            attack_types.append("data_exfiltration")

        # Sort dataset chronologically
        combined = list(zip(events, raw_logs, labels, attack_types))
        combined.sort(key=lambda item: item[0].timestamp.timestamp())

        sorted_events = [item[0] for item in combined]
        sorted_raw = [item[1] for item in combined]
        sorted_labels = [item[2] for item in combined]
        sorted_attacks = [item[3] for item in combined]

        return SyntheticDataset(
            events=sorted_events,
            raw_logs=sorted_raw,
            labels=sorted_labels,
            attack_types=sorted_attacks,
        )

    def _generate_normal_event(self, ts: datetime) -> Tuple[LogEvent, str]:
        """Generate a single benign normal operation event."""
        roll = self._rng.random()
        user = self._rng.choice(NORMAL_USERS)
        ip = self._rng.choice(NORMAL_IPS)
        port = self._rng.randint(30000, 60000)
        ts_str = ts.strftime("%b %d %H:%M:%S")

        if roll < 0.40:
            # Normal SSH login success
            raw = f"{ts_str} srv-core sshd[{self._rng.randint(1000, 9999)}]: Accepted publickey for {user} from {ip} port {port} ssh2"
            ev = LogEvent(
                timestamp=ts,
                source_type=SourceType.AUTH_LOG,
                event_type=EventType.SSH_AUTH_SUCCESS,
                src_ip=ip,
                src_port=port,
                user=user,
                action="ssh_login",
                status="success",
                raw_message=raw,
                is_anomaly=False,
            )
            return ev, raw

        elif roll < 0.65:
            # Normal Sudo command execution
            cmd = self._rng.choice([
                "/usr/bin/systemctl status nginx",
                "/usr/bin/tail -f /var/log/syslog",
                "/usr/bin/apt update",
                "/usr/bin/docker ps",
            ])
            raw = f"{ts_str} srv-core sudo:   {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
            ev = LogEvent(
                timestamp=ts,
                source_type=SourceType.AUTH_LOG,
                event_type=EventType.SUDO_COMMAND,
                user=user,
                action="sudo_exec",
                status="success",
                raw_message=raw,
                metadata={"command": cmd},
                is_anomaly=False,
            )
            return ev, raw

        elif roll < 0.95:
            # Normal balanced network JSON flow
            b_sent = self._rng.randint(1000, 50000)
            b_recv = self._rng.randint(2000, 80000)
            dur = round(self._rng.uniform(0.1, 2.0), 3)
            data = {
                "timestamp": ts.isoformat(),
                "src_ip": ip,
                "dst_ip": "192.168.1.1",
                "src_port": port,
                "dst_port": self._rng.choice([80, 443, 53, 8080]),
                "bytes_sent": b_sent,
                "bytes_recv": b_recv,
                "duration": dur,
                "status": "success",
                "event_type": "network_flow",
            }
            raw = json.dumps(data)
            ev = LogEvent(
                timestamp=ts,
                source_type=SourceType.NETWORK_JSON,
                event_type=EventType.NETWORK_FLOW,
                src_ip=ip,
                dst_ip="192.168.1.1",
                src_port=port,
                dst_port=int(str(data["dst_port"])),
                bytes_sent=b_sent,
                bytes_recv=b_recv,
                duration=dur,
                status="success",
                raw_message=raw,
                is_anomaly=False,
            )
            return ev, raw

        else:
            # Normal occasional single password typo failure
            raw = f"{ts_str} srv-core sshd[{self._rng.randint(1000, 9999)}]: Failed password for {user} from {ip} port {port} ssh2"
            ev = LogEvent(
                timestamp=ts,
                source_type=SourceType.AUTH_LOG,
                event_type=EventType.SSH_AUTH_FAIL,
                src_ip=ip,
                src_port=port,
                user=user,
                action="ssh_login",
                status="failed",
                raw_message=raw,
                is_anomaly=False,
            )
            return ev, raw

    def _generate_ssh_fail_event(
        self, ts: datetime, ip: str, port: int, user: str, is_anomaly: bool = True
    ) -> Tuple[LogEvent, str]:
        """Generate a failed SSH password attempt log entry."""
        ts_str = ts.strftime("%b %d %H:%M:%S")
        raw = f"{ts_str} srv-core sshd[{self._rng.randint(1000, 9999)}]: Failed password for {user} from {ip} port {port} ssh2"
        ev = LogEvent(
            timestamp=ts,
            source_type=SourceType.AUTH_LOG,
            event_type=EventType.SSH_AUTH_FAIL,
            src_ip=ip,
            src_port=port,
            user=user,
            action="ssh_login",
            status="failed",
            raw_message=raw,
            is_anomaly=is_anomaly,
        )
        return ev, raw

    def _generate_exfiltration_event(
        self, ts: datetime, src_ip: str, dst_ip: str, is_anomaly: bool = True
    ) -> Tuple[LogEvent, str]:
        """Generate an asymmetric high-volume outbound network flow event."""
        b_sent = self._rng.randint(15_000_000, 45_000_000)  # 15MB - 45MB
        b_recv = self._rng.randint(100, 1500)
        dur = round(self._rng.uniform(3.0, 15.0), 3)
        data = {
            "timestamp": ts.isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": self._rng.randint(40000, 65000),
            "dst_port": 443,
            "bytes_sent": b_sent,
            "bytes_recv": b_recv,
            "duration": dur,
            "status": "success",
            "event_type": "network_flow",
            "is_anomaly": is_anomaly,
        }
        raw = json.dumps(data)
        ev = LogEvent(
            timestamp=ts,
            source_type=SourceType.NETWORK_JSON,
            event_type=EventType.NETWORK_FLOW,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(str(data["src_port"])),
            dst_port=443,
            bytes_sent=b_sent,
            bytes_recv=b_recv,
            duration=dur,
            status="success",
            raw_message=raw,
            is_anomaly=is_anomaly,
        )
        return ev, raw
