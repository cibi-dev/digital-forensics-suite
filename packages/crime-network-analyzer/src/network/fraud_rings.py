"""
fraud_rings.py - Anti-Money Laundering (AML) & Fraud Ring Detection Engine.

Detects circular capital transfers (k-cycles), smurfing/structuring syndicates,
and money mule layering accounts with bounded resource constraints (CWE-400).
"""

from __future__ import annotations

import time
from typing import Any, Sequence
import networkx as nx
from pydantic import BaseModel, Field

from network.graph_store import CrimeNetworkGraph, EntityType, RelationType


class CircularTransferRing(BaseModel):
    """Represents a circular transfer ring / carousel fraud loop."""

    ring_id: str
    cycle_length: int = Field(..., ge=2)
    path: list[str] = Field(..., description="Sequence of nodes in cycle with start==end or closed path")
    total_amount: float = Field(default=0.0, ge=0.0)
    min_amount: float = Field(default=0.0, ge=0.0)
    max_amount: float = Field(default=0.0, ge=0.0)
    avg_amount: float = Field(default=0.0, ge=0.0)
    edge_details: list[dict[str, Any]] = Field(default_factory=list)


class MuleAccount(BaseModel):
    """Represents an identified money mule or layering account."""

    account_id: str
    entity_type: str
    inflow_total: float
    outflow_total: float
    inflow_tx_count: int
    outflow_tx_count: int
    flow_ratio: float = Field(description="Abs difference relative to max volume")
    velocity_score: float = Field(ge=0.0, le=1.0)
    risk_level: str = Field(description="LOW, MEDIUM, HIGH, CRITICAL")


class SmurfingPattern(BaseModel):
    """Represents a structuring / smurfing pattern (fan-in or fan-out)."""

    pattern_type: str = Field(description="FAN_IN (Aggregation) or FAN_OUT (Dispersion)")
    hub_node: str
    spoke_nodes: list[str]
    total_volume: float
    tx_count: int
    avg_tx_amount: float


class FraudReport(BaseModel):
    """Comprehensive fraud & financial crime forensic report."""

    total_cycles_detected: int
    circular_rings: list[CircularTransferRing]
    mule_accounts: list[MuleAccount]
    smurfing_patterns: list[SmurfingPattern]
    suspicious_volume_total: float
    summary: dict[str, Any] = Field(default_factory=dict)


class FraudRingDetector:
    """
    Forensic engine to uncover money laundering topologies.
    Enforces depth limits and cycle quotas to prevent resource exhaustion (CWE-400).
    """

    def __init__(self, graph: CrimeNetworkGraph) -> None:
        self.graph = graph
        self.raw_g = graph.raw_graph

    def find_circular_transfers(
        self,
        min_length: int = 3,
        max_length: int = 6,
        max_cycles: int = 1000,
        transaction_only: bool = False,
    ) -> list[CircularTransferRing]:
        """
        Finds directed simple cycles (k-cycles) with lengths between min_length and max_length.
        Bounded memory & execution time to avoid combinatorial explosion on dense graphs.
        """
        if self.raw_g.number_of_nodes() < min_length or self.raw_g.number_of_edges() < min_length:
            return []

        # Optional subgraph filtering for financial transaction relationships
        if transaction_only:
            tx_edges = [
                (u, v) for u, v, d in self.raw_g.edges(data=True)
                if str(d.get("relation_type", "")).upper() in ("TRANSACTION", "TRANSFER")
            ]
            eval_g = nx.DiGraph()
            eval_g.add_nodes_from(self.raw_g.nodes(data=True))
            eval_g.add_edges_from((u, v, self.raw_g.edges[u, v]) for u, v in tx_edges)
        else:
            eval_g = self.raw_g

        # Bounded depth-limited cycle search using canonical node ordering
        rings: list[CircularTransferRing] = []
        seen_cycles: set[tuple[str, ...]] = set()

        nodes_list = sorted(list(eval_g.nodes()))
        node_index = {n: i for i, n in enumerate(nodes_list)}

        def _dfs_cycle(
            start_node: str,
            current_node: str,
            path: list[str],
            depth: int,
        ) -> None:
            if len(rings) >= max_cycles:
                return

            if depth > max_length:
                return

            for neighbor in eval_g.successors(current_node):
                if neighbor == start_node:
                    if depth >= min_length:
                        # Found valid cycle
                        cycle_tuple = tuple(path)
                        # Canonical rotation (smallest element first)
                        min_idx = cycle_tuple.index(min(cycle_tuple))
                        canonical = cycle_tuple[min_idx:] + cycle_tuple[:min_idx]
                        if canonical not in seen_cycles:
                            seen_cycles.add(canonical)
                            
                            # Calculate cycle transaction metrics
                            closed_path = list(canonical) + [canonical[0]]
                            total_vol = 0.0
                            edge_amounts: list[float] = []
                            edge_details: list[dict[str, Any]] = []

                            for i in range(len(canonical)):
                                u = closed_path[i]
                                v = closed_path[i + 1]
                                edata = eval_g.get_edge_data(u, v) or {}
                                amt = float(edata.get("amount", edata.get("weight", 1.0)) or 1.0)
                                total_vol += amt
                                edge_amounts.append(amt)
                                edge_details.append({
                                    "source": u,
                                    "target": v,
                                    "amount": amt,
                                    "relation_type": edata.get("relation_type", "TRANSACTION"),
                                })

                            ring = CircularTransferRing(
                                ring_id=f"RING_{len(rings) + 1:04d}",
                                cycle_length=len(canonical),
                                path=closed_path,
                                total_amount=round(total_vol, 2),
                                min_amount=round(min(edge_amounts), 2) if edge_amounts else 0.0,
                                max_amount=round(max(edge_amounts), 2) if edge_amounts else 0.0,
                                avg_amount=round(total_vol / len(canonical), 2) if canonical else 0.0,
                                edge_details=edge_details,
                            )
                            rings.append(ring)
                            if len(rings) >= max_cycles:
                                return
                elif neighbor not in path and node_index[neighbor] > node_index[start_node]:
                    if depth < max_length:
                        _dfs_cycle(start_node, neighbor, path + [neighbor], depth + 1)

        for start_node in nodes_list:
            if len(rings) >= max_cycles:
                break
            _dfs_cycle(start_node, start_node, [start_node], 1)

        # Sort rings by total amount descending
        rings.sort(key=lambda r: r.total_amount, reverse=True)
        return rings

    def find_mule_accounts(
        self,
        ratio_tolerance: float = 0.25,
        min_tx_count: int = 2,
    ) -> list[MuleAccount]:
        """
        Identifies money mule / layering accounts where Inflow ~ Outflow
        with minimal balance retention and rapid transit.
        """
        mules: list[MuleAccount] = []

        for node_id in self.raw_g.nodes():
            in_edges = list(self.raw_g.in_edges(node_id, data=True))
            out_edges = list(self.raw_g.out_edges(node_id, data=True))

            in_count = len(in_edges)
            out_count = len(out_edges)

            if in_count < min_tx_count or out_count < min_tx_count:
                continue

            in_vol = sum(float(d.get("amount", d.get("weight", 1.0)) or 1.0) for _, _, d in in_edges)
            out_vol = sum(float(d.get("amount", d.get("weight", 1.0)) or 1.0) for _, _, d in out_edges)

            max_vol = max(in_vol, out_vol)
            if max_vol == 0:
                continue

            # Pass-through symmetry ratio (0 = perfectly equal inflow and outflow)
            diff_ratio = abs(in_vol - out_vol) / max_vol

            if diff_ratio <= ratio_tolerance:
                # Calculate velocity score
                velocity = (1.0 - diff_ratio) * min(1.0, (in_count + out_count) / 10.0)
                
                # Risk level classification
                if diff_ratio <= 0.05 and (in_count + out_count) >= 6:
                    risk_lvl = "CRITICAL"
                elif diff_ratio <= 0.15:
                    risk_lvl = "HIGH"
                elif diff_ratio <= 0.25:
                    risk_lvl = "MEDIUM"
                else:
                    risk_lvl = "LOW"

                ent_type = str(self.raw_g.nodes[node_id].get("entity_type", "BANK_ACCOUNT"))

                mule = MuleAccount(
                    account_id=node_id,
                    entity_type=ent_type,
                    inflow_total=round(in_vol, 2),
                    outflow_total=round(out_vol, 2),
                    inflow_tx_count=in_count,
                    outflow_tx_count=out_count,
                    flow_ratio=round(diff_ratio, 4),
                    velocity_score=round(velocity, 4),
                    risk_level=risk_lvl,
                )
                mules.append(mule)

        mules.sort(key=lambda m: m.velocity_score, reverse=True)
        return mules

    def find_smurfing_patterns(
        self,
        fan_threshold: int = 3,
    ) -> list[SmurfingPattern]:
        """
        Detects structuring/smurfing:
        - Fan-Out: 1 source sending transfers to multiple destinations.
        - Fan-In: Multiple sources sending transfers to 1 accumulator destination.
        """
        patterns: list[SmurfingPattern] = []

        for node_id in self.raw_g.nodes():
            # Check Fan-In (Aggregation)
            in_edges = list(self.raw_g.in_edges(node_id, data=True))
            if len(in_edges) >= fan_threshold:
                spoke_sources = [u for u, _, _ in in_edges]
                tot_vol = sum(float(d.get("amount", d.get("weight", 1.0)) or 1.0) for _, _, d in in_edges)
                patterns.append(
                    SmurfingPattern(
                        pattern_type="FAN_IN_AGGREGATION",
                        hub_node=node_id,
                        spoke_nodes=spoke_sources,
                        total_volume=round(tot_vol, 2),
                        tx_count=len(in_edges),
                        avg_tx_amount=round(tot_vol / len(in_edges), 2),
                    )
                )

            # Check Fan-Out (Dispersion)
            out_edges = list(self.raw_g.out_edges(node_id, data=True))
            if len(out_edges) >= fan_threshold:
                spoke_targets = [v for _, v, _ in out_edges]
                tot_vol = sum(float(d.get("amount", d.get("weight", 1.0)) or 1.0) for _, _, d in out_edges)
                patterns.append(
                    SmurfingPattern(
                        pattern_type="FAN_OUT_DISPERSION",
                        hub_node=node_id,
                        spoke_nodes=spoke_targets,
                        total_volume=round(tot_vol, 2),
                        tx_count=len(out_edges),
                        avg_tx_amount=round(tot_vol / len(out_edges), 2),
                    )
                )

        patterns.sort(key=lambda p: p.total_volume, reverse=True)
        return patterns

    def detect_all(
        self,
        min_cycle_len: int = 3,
        max_cycle_len: int = 6,
        max_cycles: int = 500,
        mule_ratio_tolerance: float = 0.25,
        fan_threshold: int = 3,
    ) -> FraudReport:
        """
        Executes full forensic suite for fraud rings, mule accounts, and smurfing.
        """
        rings = self.find_circular_transfers(
            min_length=min_cycle_len,
            max_length=max_cycle_len,
            max_cycles=max_cycles,
        )
        mules = self.find_mule_accounts(
            ratio_tolerance=mule_ratio_tolerance,
        )
        smurfing = self.find_smurfing_patterns(
            fan_threshold=fan_threshold,
        )

        suspicious_vol = sum(r.total_amount for r in rings) + sum(m.inflow_total for m in mules)

        return FraudReport(
            total_cycles_detected=len(rings),
            circular_rings=rings,
            mule_accounts=mules,
            smurfing_patterns=smurfing,
            suspicious_volume_total=round(suspicious_vol, 2),
            summary={
                "ring_count": len(rings),
                "mule_count": len(mules),
                "smurfing_count": len(smurfing),
                "critical_mules": [m.account_id for m in mules if m.risk_level == "CRITICAL"],
            },
        )
