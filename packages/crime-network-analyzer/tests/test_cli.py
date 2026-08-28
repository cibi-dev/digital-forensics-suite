"""
Unit tests for cli.py: CLI subcommands and parameter parsing.
"""

import json
from pathlib import Path
import pytest

from network.cli import main
from network.graph_store import CrimeNetworkGraph, EntityType, RelationType


@pytest.fixture
def sample_graph_json(tmp_path: Path) -> Path:
    g = CrimeNetworkGraph(name="CLITestGraph")
    g.add_node("SUSPECT_A", entity_type=EntityType.SUSPECT, label="Alice", risk_score=0.9)
    g.add_node("ACC_B", entity_type=EntityType.BANK_ACCOUNT, label="ES9121000418450200051332")
    g.add_node("ACC_C", entity_type=EntityType.BANK_ACCOUNT, label="ES9199990418450200059999")
    g.add_edge(("SUSPECT_A", "ACC_B"), relation_type=RelationType.OWNS)
    g.add_edge(("ACC_B", "ACC_C"), amount=50000.0)
    g.add_edge(("ACC_C", "ACC_B"), amount=49000.0)

    json_path = tmp_path / "sample_graph.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(g.to_dict(), f)
    return json_path


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0


def test_cli_build_from_csv(tmp_path: Path) -> None:
    nodes_csv = tmp_path / "nodes.csv"
    edges_csv = tmp_path / "edges.csv"
    out_json = tmp_path / "built.json"

    nodes_csv.write_text("id,entity_type,label,risk_score\nN1,SUSPECT,Target1,0.6\nN2,PHONE,+12345,0.1\n")
    edges_csv.write_text("source,target,relation_type,weight,amount\nN1,N2,CALL,1.0,0.0\n")

    exit_code = main(["build", "--nodes", str(nodes_csv), "--edges", str(edges_csv), "--out", str(out_json)])
    assert exit_code == 0
    assert out_json.exists()

    with open(out_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1


def test_cli_analyze(sample_graph_json: Path, tmp_path: Path) -> None:
    out_analysis = tmp_path / "analysis.json"
    exit_code = main(["analyze", "-i", str(sample_graph_json), "--top-k", "2", "--out", str(out_analysis)])
    assert exit_code == 0
    assert out_analysis.exists()

    with open(out_analysis, "r", encoding="utf-8") as f:
        analysis = json.load(f)
    assert "centrality_report" in analysis
    assert "community_report" in analysis


def test_cli_find_rings(sample_graph_json: Path, tmp_path: Path) -> None:
    out_rings = tmp_path / "rings.json"
    exit_code = main(["find-rings", "-i", str(sample_graph_json), "--min-len", "2", "--out", str(out_rings)])
    assert exit_code == 0
    assert out_rings.exists()

    with open(out_rings, "r", encoding="utf-8") as f:
        fraud_data = json.load(f)
    assert "circular_rings" in fraud_data
    assert "mule_accounts" in fraud_data


def test_cli_export(sample_graph_json: Path, tmp_path: Path) -> None:
    # GEXF Export
    out_gexf = tmp_path / "export.gexf"
    code_gexf = main(["export", "-i", str(sample_graph_json), "-f", "gexf", "-o", str(out_gexf), "--redact-pii"])
    assert code_gexf == 0
    assert out_gexf.exists()

    # GraphML Export
    out_graphml = tmp_path / "export.graphml"
    code_graphml = main(["export", "-i", str(sample_graph_json), "-f", "graphml", "-o", str(out_graphml)])
    assert code_graphml == 0
    assert out_graphml.exists()

    # JSON Export
    out_json = tmp_path / "export.json"
    code_json = main(["export", "-i", str(sample_graph_json), "-f", "json", "-o", str(out_json)])
    assert code_json == 0
    assert out_json.exists()


def test_cli_benchmark(tmp_path: Path) -> None:
    out_bench = tmp_path / "bench_cli.json"
    exit_code = main(["benchmark", "--edges", "2000", "--out", str(out_bench)])
    assert exit_code == 0
    assert out_bench.exists()

    with open(out_bench, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] in ("PASS", "FAIL")
    assert "total_time_sec" in data


def test_cli_build_from_json(sample_graph_json: Path, tmp_path: Path) -> None:
    out_json = tmp_path / "rebuilt.json"
    exit_code = main(["build", "--input-json", str(sample_graph_json), "--out", str(out_json)])
    assert exit_code == 0
    assert out_json.exists()


def test_cli_build_missing_args() -> None:
    exit_code = main(["build"])
    assert exit_code == 1
