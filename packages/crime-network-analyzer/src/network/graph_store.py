"""
graph_store.py - Criminal Network Graph Store & Entity Modeling.

Provides enterprise-grade graph data structures for modeling directed and
bipartite criminological networks (suspects, phone lines, bank accounts,
IP addresses, organizations, locations) with strict Pydantic v2 validation.
"""

from __future__ import annotations

import csv
import io
import json
import re
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Sequence

import networkx as nx
from pydantic import BaseModel, Field, field_validator


class EntityType(str, Enum):
    """Criminological entity types for graph nodes."""

    SUSPECT = "SUSPECT"
    PERSON = "PERSON"
    PHONE = "PHONE"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    IP_ADDRESS = "IP_ADDRESS"
    ORGANIZATION = "ORGANIZATION"
    LOCATION = "LOCATION"
    VEHICLE = "VEHICLE"
    CRYPTO_WALLET = "CRYPTO_WALLET"
    OTHER = "OTHER"

    @classmethod
    def _missing_(cls, value: object) -> EntityType:
        if isinstance(value, str):
            normalized = value.strip().upper().replace(" ", "_").replace("-", "_")
            for member in cls:
                if member.value == normalized:
                    return member
        return cls.OTHER


class RelationType(str, Enum):
    """Relationship / edge types in criminological networks."""

    TRANSACTION = "TRANSACTION"
    CALL = "CALL"
    COMMUNICATION = "COMMUNICATION"
    LOGIN = "LOGIN"
    ASSOCIATE_WITH = "ASSOCIATE_WITH"
    OWNS = "OWNS"
    CONTROLS = "CONTROLS"
    OPERATES = "OPERATES"
    TRAVELS_TO = "TRAVELS_TO"
    TRANSFER = "TRANSFER"
    OTHER = "OTHER"

    @classmethod
    def _missing_(cls, value: object) -> RelationType:
        if isinstance(value, str):
            normalized = value.strip().upper().replace(" ", "_").replace("-", "_")
            for member in cls:
                if member.value == normalized:
                    return member
        return cls.OTHER


class NodeData(BaseModel):
    """Validated node model for criminal entities."""

    id: str = Field(..., min_length=1, description="Unique entity identifier")
    entity_type: EntityType = Field(default=EntityType.SUSPECT, description="Type of entity")
    label: str | None = Field(default=None, description="Human readable label / name")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Risk score between 0 and 1")
    attributes: dict[str, Any] = Field(default_factory=dict, description="Additional custom attributes")

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Node ID cannot be empty or whitespace.")
        return clean

    @property
    def display_label(self) -> str:
        return self.label if self.label else self.id


class EdgeData(BaseModel):
    """Validated edge model for criminal relationships and transactions."""

    source: str = Field(..., min_length=1, description="Source node ID")
    target: str = Field(..., min_length=1, description="Target node ID")
    relation_type: RelationType = Field(default=RelationType.TRANSACTION, description="Relationship type")
    weight: float = Field(default=1.0, gt=0.0, description="Graph edge weight")
    amount: float | None = Field(default=None, ge=0.0, description="Monetary transaction amount if applicable")
    timestamp: str | None = Field(default=None, description="ISO timestamp of relation")
    attributes: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    @field_validator("source", "target")
    @classmethod
    def validate_endpoints(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Source/Target ID cannot be empty or whitespace.")
        return clean


def mask_pii_value(value: Any, pii_type: str = "general") -> str:
    """
    Sanitizes and masks PII to prevent CWE-209 information disclosure.

    Examples:
        - Name 'John Doe' -> 'J*** D***'
        - Phone '+34612345678' -> '[PHONE-***5678]'
        - IBAN 'ES9121000418450200051332' -> 'ES91****1332'
        - IP '192.168.1.100' -> '192.168.*.*'
    """
    if value is None:
        return "[REDACTED]"
    text = str(value).strip()
    if not text:
        return "[REDACTED]"

    pii_type = pii_type.lower()
    clean_text = text.replace(" ", "")

    if pii_type in ("bank_account", "iban", "account"):
        if len(clean_text) >= 8:
            return f"{clean_text[:4]}****{clean_text[-4:]}"
        return "[ACCOUNT-REDACTED]"

    if pii_type in ("phone", "phone_number"):
        digits = re.sub(r"\D", "", text)
        suffix = digits[-4:] if len(digits) >= 4 else digits
        return f"[PHONE-***{suffix}]"

    if pii_type in ("ip", "ip_address"):
        parts = text.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.*.*"
        return "[IP-REDACTED]"

    # Auto-detection heuristics for general type
    if re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$", clean_text):
        return f"{clean_text[:4]}****{clean_text[-4:]}"

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", text):
        parts = text.split(".")
        return f"{parts[0]}.{parts[1]}.*.*"

    if re.match(r"^\+?[\d\s\-()]{7,20}$", text) and any(c.isdigit() for c in text):
        digits = re.sub(r"\D", "", text)
        suffix = digits[-4:] if len(digits) >= 4 else digits
        return f"[PHONE-***{suffix}]"

    # General Name / Alias Masking
    words = text.split()
    if len(words) > 1:
        masked_words = [f"{w[0]}***" if len(w) > 1 else "***" for w in words]
        return " ".join(masked_words)

    if len(text) <= 3:
        return "***"
    return f"{text[0]}***{text[-1]}"


class CrimeNetworkGraph:
    """
    Core storage engine for criminal networks.
    Wraps NetworkX DiGraph with type validation, bipartite analysis, and forensic slicing.
    """

    def __init__(self, name: str = "CrimeNetwork") -> None:
        self.name = name
        self._graph = nx.DiGraph(name=name)

    @property
    def raw_graph(self) -> nx.DiGraph:
        """Access underlying NetworkX DiGraph."""
        return self._graph

    @property
    def num_nodes(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def num_edges(self) -> int:
        return self._graph.number_of_edges()

    @property
    def nodes(self) -> dict[str, dict[str, Any]]:
        return dict(self._graph.nodes(data=True))

    @property
    def edges(self) -> list[tuple[str, str, dict[str, Any]]]:
        return list(self._graph.edges(data=True))

    def add_node(
        self,
        node: NodeData | dict[str, Any] | str,
        entity_type: EntityType | str = EntityType.SUSPECT,
        label: str | None = None,
        risk_score: float = 0.0,
        attributes: dict[str, Any] | None = None,
    ) -> str:
        """Add a validated node to the network graph."""
        if isinstance(node, NodeData):
            node_model = node
        elif isinstance(node, dict):
            node_model = NodeData(**node)
        else:
            node_id = str(node).strip()
            ent_type = EntityType(entity_type) if isinstance(entity_type, str) else entity_type
            node_model = NodeData(
                id=node_id,
                entity_type=ent_type,
                label=label or node_id,
                risk_score=risk_score,
                attributes=attributes or {},
            )

        self._graph.add_node(
            node_model.id,
            id=node_model.id,
            entity_type=node_model.entity_type.value,
            label=node_model.display_label,
            risk_score=node_model.risk_score,
            **node_model.attributes,
        )
        return node_model.id

    def add_edge(
        self,
        edge: EdgeData | dict[str, Any] | tuple[str, str],
        relation_type: RelationType | str = RelationType.TRANSACTION,
        weight: float = 1.0,
        amount: float | None = None,
        timestamp: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """Add a validated directed edge to the network graph."""
        if isinstance(edge, EdgeData):
            edge_model = edge
        elif isinstance(edge, dict):
            edge_model = EdgeData(**edge)
        elif isinstance(edge, tuple) and len(edge) >= 2:
            rel_type = RelationType(relation_type) if isinstance(relation_type, str) else relation_type
            edge_model = EdgeData(
                source=str(edge[0]),
                target=str(edge[1]),
                relation_type=rel_type,
                weight=weight,
                amount=amount,
                timestamp=timestamp,
                attributes=attributes or {},
            )
        else:
            raise ValueError(f"Invalid edge format: {edge}")

        # Ensure endpoints exist
        if not self._graph.has_node(edge_model.source):
            self.add_node(edge_model.source, entity_type=EntityType.SUSPECT)
        if not self._graph.has_node(edge_model.target):
            self.add_node(edge_model.target, entity_type=EntityType.SUSPECT)

        edge_attrs: dict[str, Any] = {
            "relation_type": edge_model.relation_type.value,
            "weight": edge_model.weight,
            **edge_model.attributes,
        }
        if edge_model.amount is not None:
            edge_attrs["amount"] = edge_model.amount
        if edge_model.timestamp is not None:
            edge_attrs["timestamp"] = edge_model.timestamp

        self._graph.add_edge(edge_model.source, edge_model.target, **edge_attrs)
        return edge_model.source, edge_model.target

    def add_nodes_from(self, nodes: Iterable[NodeData | dict[str, Any] | str]) -> None:
        """Batch add nodes."""
        for n in nodes:
            self.add_node(n)

    def add_edges_from(self, edges: Iterable[EdgeData | dict[str, Any] | tuple[str, str]]) -> None:
        """Batch add edges."""
        for e in edges:
            self.add_edge(e)

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        """Retrieve node attributes or None if not found."""
        if self._graph.has_node(node_id):
            return dict(self._graph.nodes[node_id])
        return None

    def get_edge(self, source: str, target: str) -> dict[str, Any] | None:
        """Retrieve edge attributes or None if not found."""
        if self._graph.has_edge(source, target):
            return dict(self._graph.edges[source, target])
        return None

    def has_node(self, node_id: str) -> bool:
        return self._graph.has_node(node_id)

    def has_edge(self, source: str, target: str) -> bool:
        return self._graph.has_edge(source, target)

    def to_undirected(self) -> nx.Graph:
        """Return an undirected view/copy of the graph for symmetric algorithms."""
        return self._graph.to_undirected()

    def subgraph_by_entity_types(self, entity_types: Sequence[EntityType | str]) -> CrimeNetworkGraph:
        """Extract a filtered subgraph containing only specified entity types."""
        type_values = {t.value if isinstance(t, EntityType) else str(t).upper() for t in entity_types}
        selected_nodes = [
            n for n, d in self._graph.nodes(data=True)
            if d.get("entity_type", "").upper() in type_values
        ]
        sub_nx = self._graph.subgraph(selected_nodes).copy()
        new_cg = CrimeNetworkGraph(name=f"{self.name}_filtered")
        new_cg._graph = sub_nx
        return new_cg

    def subgraph_by_relation_types(self, relation_types: Sequence[RelationType | str]) -> CrimeNetworkGraph:
        """Extract a filtered subgraph containing only specified relation types."""
        type_values = {t.value if isinstance(t, RelationType) else str(t).upper() for t in relation_types}
        new_cg = CrimeNetworkGraph(name=f"{self.name}_rel_filtered")
        # Add all nodes
        for n, d in self._graph.nodes(data=True):
            new_cg._graph.add_node(n, **d)
        # Add matching edges
        for u, v, d in self._graph.edges(data=True):
            if d.get("relation_type", "").upper() in type_values:
                new_cg._graph.add_edge(u, v, **d)
        return new_cg

    def extract_ego_graph(self, node_id: str, radius: int = 1) -> CrimeNetworkGraph:
        """Extract ego network around a specific entity up to given radius."""
        if not self._graph.has_node(node_id):
            raise KeyError(f"Node '{node_id}' not present in graph.")
        ego_nx = nx.ego_graph(self._graph, node_id, radius=radius, undirected=True)
        new_cg = CrimeNetworkGraph(name=f"Ego_{node_id}")
        new_cg._graph = ego_nx.copy()
        return new_cg

    def is_bipartite(
        self,
        set1_types: Sequence[EntityType | str] | None = None,
        set2_types: Sequence[EntityType | str] | None = None,
    ) -> bool:
        """
        Check if the graph (or entity type partitioned graph) is bipartite.
        """
        undirected_g = self._graph.to_undirected()
        if not nx.is_bipartite(undirected_g):
            return False

        if set1_types and set2_types:
            s1_vals = {t.value if isinstance(t, EntityType) else str(t).upper() for t in set1_types}
            s2_vals = {t.value if isinstance(t, EntityType) else str(t).upper() for t in set2_types}

            for u, v in self._graph.edges():
                t_u = self._graph.nodes[u].get("entity_type", "").upper()
                t_v = self._graph.nodes[v].get("entity_type", "").upper()
                if (t_u in s1_vals and t_v in s1_vals) or (t_u in s2_vals and t_v in s2_vals):
                    return False
        return True

    def project_bipartite(
        self,
        nodes_to_keep: Sequence[str] | Sequence[EntityType | str],
        weight_attribute: str = "weight",
    ) -> CrimeNetworkGraph:
        """
        Projects a bipartite graph into a monopartite graph among the chosen set.
        For example: Suspects sharing Phones/Accounts -> Suspect-Suspect graph.
        Edge weights represent the number of shared intermediate resources.
        """
        # Determine set of primary nodes
        all_node_ids = set(self._graph.nodes())
        first_item = next(iter(nodes_to_keep), None) if nodes_to_keep else None

        if isinstance(first_item, EntityType) or (
            isinstance(first_item, str) and first_item.upper() in EntityType.__members__
        ):
            target_types = {
                t.value if isinstance(t, EntityType) else str(t).upper() for t in nodes_to_keep
            }
            primary_nodes = {
                n for n, d in self._graph.nodes(data=True)
                if d.get("entity_type", "").upper() in target_types
            }
        else:
            primary_nodes = set(str(n) for n in nodes_to_keep).intersection(all_node_ids)

        undirected_g = self._graph.to_undirected()
        projected = nx.Graph()
        for node in primary_nodes:
            if self._graph.has_node(node):
                projected.add_node(node, **self._graph.nodes[node])

        # Compute shared neighbors (intermediate assets)
        primary_list = list(primary_nodes)
        for i in range(len(primary_list)):
            u = primary_list[i]
            u_neighbors = set(undirected_g.neighbors(u)) - primary_nodes
            for j in range(i + 1, len(primary_list)):
                v = primary_list[j]
                v_neighbors = set(undirected_g.neighbors(v)) - primary_nodes
                shared = u_neighbors.intersection(v_neighbors)
                if shared:
                    projected.add_edge(
                        u,
                        v,
                        weight=float(len(shared)),
                        relation_type="CO_OCCURRENCE",
                        shared_assets=list(shared),
                    )

        # Convert to CrimeNetworkGraph (DiGraph with bidirectional edges)
        res = CrimeNetworkGraph(name=f"{self.name}_projected")
        for n, d in projected.nodes(data=True):
            res._graph.add_node(n, **d)
        for u, v, d in projected.edges(data=True):
            res._graph.add_edge(u, v, **d)
            res._graph.add_edge(v, u, **d)
        return res

    def redact_pii(self) -> CrimeNetworkGraph:
        """
        Creates an anonymized, redacted copy of the graph (CWE-209 mitigation).
        Masks labels, IDs, phone numbers, accounts, and IPs in node/edge attributes.
        """
        redacted = CrimeNetworkGraph(name=f"{self.name}_redacted")
        for node_id, data in self._graph.nodes(data=True):
            ent_type = data.get("entity_type", "SUSPECT")
            label = data.get("label", node_id)
            masked_label = mask_pii_value(label, pii_type=ent_type)
            masked_attrs = {
                k: mask_pii_value(v, pii_type=k) if isinstance(v, str) and k in ("phone", "iban", "account", "ip", "name", "address") else v
                for k, v in data.items()
                if k not in ("id", "entity_type", "label", "risk_score")
            }
            redacted.add_node(
                node_id,
                entity_type=ent_type,
                label=masked_label,
                risk_score=data.get("risk_score", 0.0),
                attributes=masked_attrs,
            )

        for u, v, data in self._graph.edges(data=True):
            redacted._graph.add_edge(u, v, **data)

        return redacted

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to dictionary."""
        return {
            "name": self.name,
            "nodes": [
                {
                    "id": n,
                    "entity_type": d.get("entity_type", EntityType.SUSPECT.value),
                    "label": d.get("label", n),
                    "risk_score": d.get("risk_score", 0.0),
                    "attributes": {k: v for k, v in d.items() if k not in ("id", "entity_type", "label", "risk_score")},
                }
                for n, d in self._graph.nodes(data=True)
            ],
            "edges": [
                {
                    "source": u,
                    "target": v,
                    "relation_type": d.get("relation_type", RelationType.TRANSACTION.value),
                    "weight": d.get("weight", 1.0),
                    "amount": d.get("amount"),
                    "timestamp": d.get("timestamp"),
                    "attributes": {k: v for k, v in d.items() if k not in ("relation_type", "weight", "amount", "timestamp")},
                }
                for u, v, d in self._graph.edges(data=True)
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CrimeNetworkGraph:
        """Instantiate CrimeNetworkGraph from dictionary with Pydantic validation."""
        cg = cls(name=data.get("name", "CrimeNetwork"))
        for n_data in data.get("nodes", []):
            node_model = NodeData(**n_data)
            cg.add_node(node_model)
        for e_data in data.get("edges", []):
            edge_model = EdgeData(**e_data)
            cg.add_edge(edge_model)
        return cg

    @classmethod
    def from_json(cls, json_content: str | Path) -> CrimeNetworkGraph:
        """Load CrimeNetworkGraph from JSON string or file path."""
        if isinstance(json_content, Path) or (isinstance(json_content, str) and Path(json_content).is_file()):
            with open(json_content, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = json.loads(str(json_content))
        return cls.from_dict(data)

    @classmethod
    def from_csv(
        cls,
        nodes_csv: str | Path,
        edges_csv: str | Path,
        name: str = "CrimeNetworkFromCSV",
    ) -> CrimeNetworkGraph:
        """
        Load CrimeNetworkGraph from CSV files for nodes and edges.
        """
        cg = cls(name=name)

        # Parse nodes
        nodes_path = Path(nodes_csv)
        with open(nodes_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                node_id = row.get("id") or row.get("node_id") or row.get("name")
                if not node_id:
                    continue
                ent_type = row.get("entity_type") or row.get("type") or "SUSPECT"
                label = row.get("label") or node_id
                risk_score = float(row.get("risk_score", 0.0) or 0.0)
                attrs = {k: v for k, v in row.items() if k not in ("id", "node_id", "entity_type", "type", "label", "risk_score")}
                cg.add_node(
                    node_id,
                    entity_type=ent_type,
                    label=label,
                    risk_score=risk_score,
                    attributes=attrs,
                )

        # Parse edges
        edges_path = Path(edges_csv)
        with open(edges_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                source = row.get("source") or row.get("src") or row.get("from")
                target = row.get("target") or row.get("dst") or row.get("to")
                if not source or not target:
                    continue
                rel_type = row.get("relation_type") or row.get("type") or "TRANSACTION"
                weight = float(row.get("weight", 1.0) or 1.0)
                amount = float(row["amount"]) if row.get("amount") else None
                timestamp = row.get("timestamp") or row.get("date")
                attrs = {k: v for k, v in row.items() if k not in ("source", "src", "from", "target", "dst", "to", "relation_type", "type", "weight", "amount", "timestamp", "date")}
                cg.add_edge(
                    (source, target),
                    relation_type=rel_type,
                    weight=weight,
                    amount=amount,
                    timestamp=timestamp,
                    attributes=attrs,
                )

        return cg
