#!/usr/bin/env python3
"""
Generate a deterministic network topology for N operator nodes.

Outputs JSON with node definitions (names, seeds, ports) and per-ledger
quorum membership assignments. The topology is deterministic for a given
(nodes, ledgers_per_op) pair but deliberately asymmetric — quorum sizes
vary between 3 and 5, and different ledgers of the same operator get
different member sets.

Algorithm:
  N <= 5:  full mesh (every other operator is a quorum member)
  N >  5:  "ring + seeded extras"
    1. Ring neighbors (i-1, i+1 mod N) guarantee connectivity
    2. Target quorum size per ledger: deterministic 3/4/5 (weighted 50/30/20%)
    3. Extra members drawn from a deterministic shuffle of remaining operators

Usage:
  python3 generate-topology.py --nodes 4 --ledgers-per-op 3
  python3 generate-topology.py --nodes 8 --ledgers-per-op 3 --show-graph
"""

import argparse
import hashlib
import json
import sys

NAMES = [
    "alice", "bob", "charlie", "diana", "eve", "frank", "grace", "hank",
    "iris", "jack", "kate", "leo", "mia", "nate", "olive", "pat",
    "quinn", "rosa", "sam", "tara", "uri", "val", "wendy", "xander",
    "yara", "zane",
]

# Exact backward-compatible seeds for the first 5 nodes
LEGACY_SEEDS = {
    "alice":   "416c696365000000000000000000000000000000000000000000000000000001",
    "bob":     "426f620000000000000000000000000000000000000000000000000000000002",
    "charlie": "436861726c696500000000000000000000000000000000000000000000000003",
    "diana":   "4469616e61000000000000000000000000000000000000000000000000000004",
    "eve":     "4576650000000000000000000000000000000000000000000000000000000005",
}


def node_name(index: int) -> str:
    """1-based index to node name."""
    if index <= len(NAMES):
        return NAMES[index - 1]
    return f"node{index}"


def node_seed(index: int, name: str) -> str:
    """Deterministic 64-hex-char seed. Backward-compatible for first 5."""
    if name in LEGACY_SEEDS:
        return LEGACY_SEEDS[name]
    # Encode name as hex (up to 27 bytes = 54 hex chars), pad, append index
    name_hex = name.encode().hex()[:54]
    return f"{name_hex:0<54}{index:010x}"


def det_hash(key: str) -> int:
    """Deterministic hash from a string key. Returns a large positive int."""
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16)


def generate_quorum(n: int, ledgers_per_op: int) -> dict:
    """
    Generate quorum membership for each operator's ledgers.
    Returns dict: { "alice_1": ["bob", "charlie", "diana"], ... }
    """
    names = [node_name(i) for i in range(1, n + 1)]
    quorum = {}

    for i, op in enumerate(names):
        for lid in range(1, ledgers_per_op + 1):
            key = f"{op}_{lid}"

            if n <= 5:
                # Full mesh: all other operators
                members = [x for x in names if x != op]
            else:
                # Ring base: prev and next neighbor
                prev = names[(i - 1) % n]
                nxt = names[(i + 1) % n]
                members = [prev, nxt]

                # Deterministic target size: 3 (50%), 4 (30%), 5 (20%)
                h = det_hash(f"{i}.{lid}.size")
                r = h % 10
                if r < 5:
                    target = 3
                elif r < 8:
                    target = 4
                else:
                    target = 5
                target = min(target, n - 1)

                # Fill extras from deterministically-shuffled candidates
                extras_needed = target - len(members)
                if extras_needed > 0:
                    candidates = [x for x in names if x != op and x not in members]
                    candidates.sort(key=lambda c: det_hash(f"{i}.{lid}.{c}"))
                    members += candidates[:extras_needed]

            quorum[key] = members

    # Validation: every node must be a quorum member somewhere
    all_members = set()
    for members in quorum.values():
        all_members.update(members)
    for name in names:
        if name not in all_members:
            # Force-add to a deterministic other operator's first ledger
            target_idx = det_hash(f"fixup.{name}") % n
            target_op = names[target_idx]
            if target_op == name:
                target_op = names[(target_idx + 1) % n]
            target_key = f"{target_op}_1"
            if name not in quorum[target_key]:
                quorum[target_key].append(name)

    return quorum


def show_graph(names, quorum, ledgers_per_op):
    """Print a human-readable topology summary to stderr."""
    n = len(names)

    # Per-node: how many ledgers is this node a member of?
    membership_count = {name: 0 for name in names}
    size_dist = {}
    for key, members in quorum.items():
        sz = len(members)
        size_dist[sz] = size_dist.get(sz, 0) + 1
        for m in members:
            membership_count[m] += 1

    print(f"\n{'='*60}", file=sys.stderr)
    print(f" Topology: {n} nodes, {ledgers_per_op} ledgers/op", file=sys.stderr)
    print(f" Total ledgers: {n * ledgers_per_op}", file=sys.stderr)
    print(f" Quorum sizes: {dict(sorted(size_dist.items()))}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    for name in names:
        op_ledgers = []
        for lid in range(1, ledgers_per_op + 1):
            key = f"{name}_{lid}"
            members = quorum[key]
            op_ledgers.append(f"  {key}: [{', '.join(members)}]")
        member_of = membership_count[name]
        print(f"\n {name} (member of {member_of} other ledgers):", file=sys.stderr)
        for line in op_ledgers:
            print(line, file=sys.stderr)

    print(f"\n{'='*60}\n", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Generate network topology")
    parser.add_argument("--nodes", type=int, default=4, help="Number of operator nodes")
    parser.add_argument("--ledgers-per-op", type=int, default=3, help="Ledgers per operator")
    parser.add_argument("--show-graph", action="store_true", help="Print topology graph to stderr")
    args = parser.parse_args()

    n = args.nodes
    lpo = args.ledgers_per_op

    if n < 3:
        print("Error: need at least 3 nodes for quorum", file=sys.stderr)
        sys.exit(1)

    names = [node_name(i) for i in range(1, n + 1)]
    quorum = generate_quorum(n, lpo)

    nodes = []
    for i in range(1, n + 1):
        name = node_name(i)
        nodes.append({
            "index": i,
            "name": name,
            "seed": node_seed(i, name),
            "relay_port": 7800 + i,
            "metrics_port": 9100 + i,
        })

    topology = {
        "node_count": n,
        "ledgers_per_op": lpo,
        "nodes": nodes,
        "quorum": quorum,
    }

    if args.show_graph:
        show_graph(names, quorum, lpo)

    json.dump(topology, sys.stdout, indent=2)
    print()  # trailing newline


if __name__ == "__main__":
    main()
