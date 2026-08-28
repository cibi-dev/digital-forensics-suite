"""
Tests for custody.merkle module: balanced binary Merkle tree, O(log N) inclusion proofs,
tamper detection, and constant-time verification.
"""

import pytest

from custody.hasher import hash_bytes
from custody.merkle import (
    AuditPathNode,
    MerkleProof,
    MerkleTree,
    _hash_pair,
    verify_merkle_proof,
)


def _flip_first_char(hex_str: str) -> str:
    """Flip first character to guarantee 1-char tamper."""
    c0 = hex_str[0]
    flipped = "1" if c0 != "1" else "2"
    return flipped + hex_str[1:]


def test_empty_merkle_tree() -> None:
    tree = MerkleTree([], algorithm="sha256")
    assert tree.leaf_count == 0
    assert tree.root == hash_bytes(b"", algorithm="sha256")
    assert tree.height == 1

    with pytest.raises(ValueError, match="Cannot generate inclusion proof"):
        tree.get_proof(0)


def test_single_leaf_merkle_tree() -> None:
    leaf = hash_bytes(b"item-01", algorithm="sha256")
    tree = MerkleTree([leaf], algorithm="sha256", is_prehashed=True)
    assert tree.leaf_count == 1
    assert tree.root == leaf
    assert tree.height == 1

    proof = tree.get_proof(0)
    assert proof.leaf_index == 0
    assert proof.leaf_hash == leaf
    assert proof.audit_path == []
    assert proof.root_hash == leaf
    assert proof.verify() is True


def test_two_leaves_merkle_tree() -> None:
    l0 = hash_bytes(b"item-00", algorithm="sha256")
    l1 = hash_bytes(b"item-01", algorithm="sha256")
    tree = MerkleTree([l0, l1], algorithm="sha256", is_prehashed=True)

    assert tree.leaf_count == 2
    assert tree.height == 2
    assert len(tree.levels) == 2

    # Proof for leaf 0
    proof0 = tree.get_proof(0)
    assert len(proof0.audit_path) == 1
    assert proof0.audit_path[0].position == "right"
    assert proof0.audit_path[0].hash == l1
    assert proof0.verify() is True

    # Proof for leaf 1
    proof1 = tree.get_proof(1)
    assert len(proof1.audit_path) == 1
    assert proof1.audit_path[0].position == "left"
    assert proof1.audit_path[0].hash == l0
    assert proof1.verify() is True


@pytest.mark.parametrize("leaf_count", [3, 4, 5, 7, 8, 9, 15, 16, 31, 32, 64])
def test_merkle_tree_inclusion_proofs_all_sizes(leaf_count: int) -> None:
    leaves = [hash_bytes(f"item-{i}".encode("utf-8"), algorithm="sha256") for i in range(leaf_count)]
    tree = MerkleTree(leaves, algorithm="sha256", is_prehashed=True)

    assert tree.leaf_count == leaf_count
    assert len(tree.root) == 64

    for i in range(leaf_count):
        proof = tree.get_proof(i)
        assert proof.leaf_index == i
        assert proof.leaf_hash == leaves[i]
        assert proof.root_hash == tree.root
        assert proof.verify() is True
        assert verify_merkle_proof(proof) is True


def test_merkle_tamper_detection_leaf_hash() -> None:
    leaves = [hash_bytes(f"sample-{i}".encode(), algorithm="sha256") for i in range(4)]
    tree = MerkleTree(leaves, algorithm="sha256", is_prehashed=True)
    proof = tree.get_proof(1)
    assert proof.verify() is True

    # Tamper 1 character of the leaf hash
    tampered_leaf_hash = _flip_first_char(proof.leaf_hash)
    tampered_proof = MerkleProof(
        leaf_index=proof.leaf_index,
        leaf_hash=tampered_leaf_hash,
        audit_path=proof.audit_path,
        root_hash=proof.root_hash,
        algorithm=proof.algorithm,
        total_leaves=proof.total_leaves,
    )
    assert tampered_proof.verify() is False


def test_merkle_tamper_detection_audit_path_sibling() -> None:
    leaves = [hash_bytes(f"sample-{i}".encode(), algorithm="sha256") for i in range(4)]
    tree = MerkleTree(leaves, algorithm="sha256", is_prehashed=True)
    proof = tree.get_proof(2)
    assert proof.verify() is True

    # Tamper 1 character of a sibling in audit path
    tampered_path = [
        AuditPathNode(
            hash_value=_flip_first_char(proof.audit_path[0].hash),
            position=proof.audit_path[0].position,
        ),
        proof.audit_path[1],
    ]
    tampered_proof = MerkleProof(
        leaf_index=proof.leaf_index,
        leaf_hash=proof.leaf_hash,
        audit_path=tampered_path,
        root_hash=proof.root_hash,
        algorithm=proof.algorithm,
        total_leaves=proof.total_leaves,
    )
    assert tampered_proof.verify() is False


def test_merkle_tamper_detection_root_hash() -> None:
    leaves = [hash_bytes(f"sample-{i}".encode(), algorithm="sha256") for i in range(4)]
    tree = MerkleTree(leaves, algorithm="sha256", is_prehashed=True)
    proof = tree.get_proof(0)

    tampered_root = _flip_first_char(proof.root_hash)
    tampered_proof = MerkleProof(
        leaf_index=proof.leaf_index,
        leaf_hash=proof.leaf_hash,
        audit_path=proof.audit_path,
        root_hash=tampered_root,
        algorithm=proof.algorithm,
        total_leaves=proof.total_leaves,
    )
    assert tampered_proof.verify() is False


def test_merkle_tamper_detection_position_inversion() -> None:
    leaves = [hash_bytes(f"sample-{i}".encode(), algorithm="sha256") for i in range(4)]
    tree = MerkleTree(leaves, algorithm="sha256", is_prehashed=True)
    proof = tree.get_proof(1)

    # Invert sibling position from 'left' to 'right'
    inverted_path = [
        AuditPathNode(
            hash_value=proof.audit_path[0].hash,
            position="right" if proof.audit_path[0].position == "left" else "left",
        ),
        proof.audit_path[1],
    ]
    tampered_proof = MerkleProof(
        leaf_index=proof.leaf_index,
        leaf_hash=proof.leaf_hash,
        audit_path=inverted_path,
        root_hash=proof.root_hash,
        algorithm=proof.algorithm,
        total_leaves=proof.total_leaves,
    )
    assert tampered_proof.verify() is False


def test_merkle_proof_serialization() -> None:
    leaves = [hash_bytes(f"data-{i}".encode(), algorithm="sha256") for i in range(3)]
    tree = MerkleTree(leaves, algorithm="sha256", is_prehashed=True)
    original_proof = tree.get_proof(1)

    proof_dict = original_proof.to_dict()
    restored_proof = MerkleProof.from_dict(proof_dict)

    assert restored_proof.leaf_index == original_proof.leaf_index
    assert restored_proof.leaf_hash == original_proof.leaf_hash
    assert restored_proof.root_hash == original_proof.root_hash
    assert restored_proof.verify() is True


def test_merkle_tree_blake3() -> None:
    leaves = [hash_bytes(f"b3-{i}".encode(), algorithm="blake3") for i in range(5)]
    tree = MerkleTree(leaves, algorithm="blake3", is_prehashed=True)
    assert tree.leaf_count == 5

    for i in range(5):
        proof = tree.get_proof(i)
        assert proof.algorithm == "blake3"
        assert proof.verify() is True


def test_merkle_tree_raw_bytes_leaves() -> None:
    raw_leaves = [b"raw_chunk_0", b"raw_chunk_1", b"raw_chunk_2"]
    tree = MerkleTree(raw_leaves, algorithm="sha256", is_prehashed=False)
    assert tree.leaf_count == 3

    for i in range(3):
        proof = tree.get_proof(i)
        assert proof.verify() is True


def test_merkle_tree_string_leaves_not_prehashed() -> None:
    str_leaves = ["raw_string_0", "raw_string_1"]
    tree = MerkleTree(str_leaves, algorithm="sha256", is_prehashed=False)
    assert tree.leaf_count == 2
    assert tree.get_proof(0).verify() is True


def test_merkle_hash_pair_non_hex_fallback() -> None:
    # Non-hex string combination fallback
    combined = _hash_pair("not_hex_left", "not_hex_right", "sha256")
    assert len(combined) == 64


def test_merkle_tree_index_errors() -> None:
    tree = MerkleTree(["a" * 64, "b" * 64], algorithm="sha256", is_prehashed=True)
    with pytest.raises(IndexError):
        tree.get_leaf(-1)
    with pytest.raises(IndexError):
        tree.get_leaf(2)
    with pytest.raises(IndexError):
        tree.get_proof(-1)
    with pytest.raises(IndexError):
        tree.get_proof(2)


def test_audit_path_node_validation() -> None:
    with pytest.raises(ValueError, match="Position must be 'left' or 'right'"):
        AuditPathNode(hash_value="abc", position="top")  # type: ignore[arg-type]

    node1 = AuditPathNode(hash_value="abc", position="left")
    node2 = AuditPathNode(hash_value="abc", position="left")
    node3 = AuditPathNode(hash_value="def", position="left")
    assert node1 == node2
    assert node1 != node3
    assert node1 != "not_a_node"
    assert "AuditPathNode" in repr(node1)


def test_merkle_proof_validation() -> None:
    with pytest.raises(ValueError, match="leaf_index must be non-negative"):
        MerkleProof(leaf_index=-1, leaf_hash="a"*64, audit_path=[], root_hash="b"*64, total_leaves=2)
    with pytest.raises(ValueError, match="total_leaves must be at least 1"):
        MerkleProof(leaf_index=0, leaf_hash="a"*64, audit_path=[], root_hash="b"*64, total_leaves=0)
    with pytest.raises(ValueError, match="cannot exceed total_leaves-1"):
        MerkleProof(leaf_index=5, leaf_hash="a"*64, audit_path=[], root_hash="b"*64, total_leaves=3)
    with pytest.raises(TypeError, match="Invalid audit path node type"):
        MerkleProof(leaf_index=0, leaf_hash="a"*64, audit_path=[123], root_hash="b"*64, total_leaves=1)  # type: ignore[list-item]
