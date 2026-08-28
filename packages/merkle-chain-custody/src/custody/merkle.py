"""
Balanced Binary Merkle Tree implementation for ISO/IEC 27037 forensic custody.
Provides deterministic tree construction, root computation, O(log N) inclusion proofs,
and constant-time verification with 1-byte tamper detection.
"""

from __future__ import annotations

import hmac
from typing import Any, Dict, List, Literal, Optional, Sequence, Union

from custody.hasher import HashAlgorithm, StreamingHasher, hash_bytes, verify_digest


def _hash_pair(left_hex: str, right_hex: str, algorithm: Union[HashAlgorithm, str]) -> str:
    """
    Cryptographically combine and hash two child nodes.
    Applies domain separation (0x01 prefix) to prevent second preimage attacks.
    """
    hasher = StreamingHasher(algorithm=algorithm)
    hasher.update(b"\x01")  # Internal node prefix domain separator
    try:
        left_bytes = bytes.fromhex(left_hex)
    except ValueError:
        left_bytes = left_hex.encode("utf-8")
    try:
        right_bytes = bytes.fromhex(right_hex)
    except ValueError:
        right_bytes = right_hex.encode("utf-8")

    hasher.update(left_bytes)
    hasher.update(right_bytes)
    return hasher.hexdigest()


def _hash_leaf(data: Union[str, bytes], algorithm: Union[HashAlgorithm, str], is_prehashed: bool = False) -> str:
    """
    Hash a leaf node with domain separation (0x00 prefix) if not prehashed.
    """
    if is_prehashed and isinstance(data, str):
        return data.lower()
    
    hasher = StreamingHasher(algorithm=algorithm)
    hasher.update(b"\x00")  # Leaf node prefix domain separator
    if isinstance(data, str):
        hasher.update(data.encode("utf-8"))
    else:
        hasher.update(data)
    return hasher.hexdigest()


class AuditPathNode:
    """Represents a single step in a Merkle inclusion proof."""
    
    def __init__(self, hash_value: str, position: Literal["left", "right"]) -> None:
        if position not in ("left", "right"):
            raise ValueError(f"Position must be 'left' or 'right', got '{position}'")
        self.hash: str = hash_value.lower()
        self.position: Literal["left", "right"] = position

    def to_dict(self) -> Dict[str, str]:
        return {"hash": self.hash, "position": self.position}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuditPathNode:
        return cls(hash_value=data["hash"], position=data["position"])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AuditPathNode):
            return False
        return hmac.compare_digest(self.hash, other.hash) and self.position == other.position

    def __repr__(self) -> str:
        return f"AuditPathNode(hash='{self.hash[:8]}...', position='{self.position}')"


class MerkleProof:
    """
    Cryptographic Merkle inclusion proof for forensic verification.
    """

    def __init__(
        self,
        leaf_index: int,
        leaf_hash: str,
        audit_path: Sequence[Union[AuditPathNode, Dict[str, str]]],
        root_hash: str,
        algorithm: Union[HashAlgorithm, str] = HashAlgorithm.SHA256,
        total_leaves: int = 1,
    ) -> None:
        if leaf_index < 0:
            raise ValueError(f"leaf_index must be non-negative, got {leaf_index}")
        if total_leaves < 1:
            raise ValueError(f"total_leaves must be at least 1, got {total_leaves}")
        if leaf_index >= total_leaves:
            raise ValueError(f"leaf_index ({leaf_index}) cannot exceed total_leaves-1 ({total_leaves-1})")

        self.leaf_index: int = leaf_index
        self.leaf_hash: str = leaf_hash.lower()
        self.root_hash: str = root_hash.lower()
        self.total_leaves: int = total_leaves
        
        algo_str = str(algorithm).lower()
        self.algorithm: str = "blake3" if "blake3" in algo_str else "sha256"

        self.audit_path: List[AuditPathNode] = []
        for node in audit_path:
            if isinstance(node, AuditPathNode):
                self.audit_path.append(node)
            elif isinstance(node, dict):
                self.audit_path.append(AuditPathNode.from_dict(node))
            else:
                raise TypeError(f"Invalid audit path node type: {type(node).__name__}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash,
            "audit_path": [node.to_dict() for node in self.audit_path],
            "root_hash": self.root_hash,
            "algorithm": self.algorithm,
            "total_leaves": self.total_leaves,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MerkleProof:
        return cls(
            leaf_index=data["leaf_index"],
            leaf_hash=data["leaf_hash"],
            audit_path=data["audit_path"],
            root_hash=data["root_hash"],
            algorithm=data.get("algorithm", "sha256"),
            total_leaves=data.get("total_leaves", 1),
        )

    def verify(self) -> bool:
        """Verify this inclusion proof against its root hash in constant time."""
        return verify_merkle_proof(self)


def verify_merkle_proof(proof: MerkleProof) -> bool:
    """
    Verify a Merkle inclusion proof in O(log N) operations.
    Uses constant-time comparison (CWE-208 defense).
    """
    current_hash = proof.leaf_hash.lower()
    
    for step in proof.audit_path:
        if step.position == "left":
            current_hash = _hash_pair(step.hash, current_hash, proof.algorithm)
        elif step.position == "right":
            current_hash = _hash_pair(current_hash, step.hash, proof.algorithm)
        else:
            return False

    return verify_digest(current_hash, proof.root_hash)


class MerkleTree:
    """
    Balanced Binary Merkle Tree for cryptographic audit trails and integrity trees.
    """

    def __init__(
        self,
        leaves: Sequence[Union[str, bytes]],
        algorithm: Union[HashAlgorithm, str] = HashAlgorithm.SHA256,
        is_prehashed: bool = True,
    ) -> None:
        algo_str = str(algorithm).lower()
        self.algorithm: HashAlgorithm = (
            HashAlgorithm.BLAKE3 if "blake3" in algo_str else HashAlgorithm.SHA256
        )
        self.is_prehashed: bool = is_prehashed
        
        # Build leaf list
        self._raw_leaves = list(leaves)
        self._levels: List[List[str]] = []
        self._build_tree()

    def _build_tree(self) -> None:
        if not self._raw_leaves:
            # Empty tree root is hash of empty string
            empty_root = hash_bytes(b"", algorithm=self.algorithm)
            self._levels = [[empty_root]]
            return

        # Level 0: processed leaf hashes
        leaf_hashes = [
            _hash_leaf(leaf, algorithm=self.algorithm, is_prehashed=self.is_prehashed)
            for leaf in self._raw_leaves
        ]
        self._levels = [leaf_hashes]

        current_level = leaf_hashes
        while len(current_level) > 1:
            next_level: List[str] = []
            num_nodes = len(current_level)
            for i in range(0, num_nodes, 2):
                if i + 1 < num_nodes:
                    parent_hash = _hash_pair(
                        current_level[i], current_level[i + 1], algorithm=self.algorithm
                    )
                    next_level.append(parent_hash)
                else:
                    # Lone node promoted to avoid duplicate-leaf malleability
                    next_level.append(current_level[i])
            self._levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        """Root hexadecimal hash of the Merkle Tree."""
        if not self._levels or not self._levels[-1]:
            return hash_bytes(b"", algorithm=self.algorithm)
        return self._levels[-1][0]

    @property
    def leaf_count(self) -> int:
        """Total number of leaves in the tree."""
        return len(self._raw_leaves)

    @property
    def height(self) -> int:
        """Height of the Merkle tree (number of levels)."""
        return len(self._levels)

    @property
    def levels(self) -> List[List[str]]:
        """All levels of the tree from leaves (level 0) to root (level -1)."""
        return [list(lvl) for lvl in self._levels]

    def get_leaf(self, index: int) -> str:
        """Get the processed leaf hash at index."""
        if index < 0 or index >= len(self._levels[0]):
            raise IndexError(f"Leaf index {index} out of range [0, {len(self._levels[0]) - 1}]")
        return self._levels[0][index]

    def get_proof(self, leaf_index: int) -> MerkleProof:
        """
        Generate an O(log N) Merkle inclusion proof for the leaf at `leaf_index`.
        """
        if not self._raw_leaves:
            raise ValueError("Cannot generate inclusion proof for an empty Merkle tree")
        if leaf_index < 0 or leaf_index >= len(self._raw_leaves):
            raise IndexError(
                f"Leaf index {leaf_index} out of range [0, {len(self._raw_leaves) - 1}]"
            )

        audit_path: List[AuditPathNode] = []
        curr_idx = leaf_index

        for level_idx in range(len(self._levels) - 1):
            level = self._levels[level_idx]
            is_right_child = (curr_idx % 2 == 1)

            if is_right_child:
                sibling_idx = curr_idx - 1
                audit_path.append(AuditPathNode(hash_value=level[sibling_idx], position="left"))
            else:
                sibling_idx = curr_idx + 1
                if sibling_idx < len(level):
                    audit_path.append(
                        AuditPathNode(hash_value=level[sibling_idx], position="right")
                    )
                # If sibling_idx >= len(level), this node was promoted, so no sibling at this level

            curr_idx = curr_idx // 2

        return MerkleProof(
            leaf_index=leaf_index,
            leaf_hash=self.get_leaf(leaf_index),
            audit_path=audit_path,
            root_hash=self.root,
            algorithm=self.algorithm,
            total_leaves=len(self._raw_leaves),
        )
