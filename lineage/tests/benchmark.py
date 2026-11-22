"""Performance, Scalability, and Security Microbenchmark Suite for LCT.

Measures real cryptographic execution metrics on the current machine:
1. Offline per-hop attenuation latency (ES256 signing + canonical SHA-256 chaining)
2. Token wire size scaling across hop depths d in {1, 2, 3, 5, 8} & MultiParentToken
3. LeafVerifier p50 / p95 / p99 latency (µs) and throughput (ops/sec) across:
   - `LEAF_ONLY`
   - `LOCAL_FULL_CHAIN` (depths 1, 3, 5, 8)
   - `ADAPTIVE_RISK_ANCHORED` (LOW_RISK fast path vs HIGH_RISK HTTP revocation anchor)
   - `MultiParentToken` (3-parent converging DAG evaluation)
4. `LineagePrefixTrie` O(depth) lookup latency at 10,000 active revoked prefixes
"""

from __future__ import annotations

import json
import statistics
import time
from pathlib import Path
from typing import Any, Dict, List

from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.protocol import (
    MultiParentToken,
    PermissionLattice,
    create_dpop_proof,
    mint_root_token,
)
from lineage.revocation import (
    LineagePrefixTrie,
    RevocationReplicaClient,
    RevocationService,
)
from lineage.verifier import LeafVerifier, VerificationMode


def _percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, int(round((pct / 100.0) * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


def _summarize_us(samples_us: List[float]) -> Dict[str, float]:
    s = sorted(samples_us)
    mean_us = statistics.fmean(s)
    return {
        "p50_us": round(_percentile(s, 50), 2),
        "p95_us": round(_percentile(s, 95), 2),
        "p99_us": round(_percentile(s, 99), 2),
        "mean_us": round(mean_us, 2),
        "ops_per_sec": round(1_000_000.0 / mean_us, 1) if mean_us > 0 else 0.0,
    }


def run_benchmarks(iterations: int = 200) -> Dict[str, Any]:
    ca_alpha = TrustDomainCA("org-alpha.io", alg="ES256")
    ca_beta = TrustDomainCA("org-beta.io", alg="ES256")
    ca_pay = TrustDomainCA("org-payment.io", alg="ES256")
    resolver = TrustBundleResolver()
    for ca in (ca_alpha, ca_beta, ca_pay):
        resolver.register_domain_ca(ca)

    cas_cycle = [ca_alpha, ca_beta, ca_pay]
    w_drv = ca_alpha.issue_workload("/ns/entry/sa/driver")
    w_tool = ca_pay.issue_workload("/ns/tools/sa/bench-tool")
    w_rev = ca_alpha.issue_workload("/ns/sys/sa/rev-bench")

    # Pre-provision chain agents up to depth 8
    agents = [
        cas_cycle[i % 3].issue_workload(f"/ns/mesh/sa/agent-hop-{i}")
        for i in range(9)
    ]

    base_lattice = PermissionLattice.create(
        tools=["get_weather", "execute_payment", "write_ledger"],
        max_amount=1000.0,
        allowed_scopes=["read", "pay"],
        param_whitelist={"city": ["New York", "London"]},
        max_calls=100_000,
    )

    # 1. Benchmark offline hop attenuation latency
    t_root = mint_root_token(
        ca_alpha,
        "bench-task",
        "user:alice",
        w_drv.jkt,
        agents[0].spiffe_id,
        agents[0].jkt,
        base_lattice,
        max_depth=10,
        hop_segment="H0",
    )
    attenuate_samples_us: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = t_root.attenuate(
            agents[0],
            agents[1].spiffe_id,
            agents[1].jkt,
            base_lattice,
            hop_segment="H1",
        )
        attenuate_samples_us.append((time.perf_counter() - t0) * 1_000_000.0)

    # 2. Build tokens of depths 1, 2, 3, 5, 8 and measure compact wire sizes
    tokens_by_depth: Dict[int, tuple] = {}
    cur_tok = t_root
    tokens_by_depth[0] = (cur_tok, agents[0])
    for d in range(1, 9):
        narrowed = PermissionLattice.create(
            tools=["get_weather", "execute_payment", "write_ledger"],
            max_amount=float(1000 - d * 50),
            allowed_scopes=["read", "pay"],
            param_whitelist={"city": ["New York"]},
            max_calls=100_000,
        )
        cur_tok = cur_tok.attenuate(
            agents[d - 1],
            agents[d].spiffe_id,
            agents[d].jkt,
            narrowed,
            hop_segment=f"H{d}",
        )
        tokens_by_depth[d] = (cur_tok, agents[d])

    token_sizes_bytes = {
        f"depth_{d}": len(tokens_by_depth[d][0].encode_compact().encode("ascii"))
        for d in (0, 1, 2, 3, 5, 8)
    }

    # 3. Benchmark Verification Modes over HTTP RevocationService
    rev_svc = RevocationService(w_rev, resolver)
    rev_url = rev_svc.start()
    htu = "http://127.0.0.1:19999/mcp"

    try:
        replica = RevocationReplicaClient(rev_url, resolver)
        v_leaf = LeafVerifier(
            w_tool.spiffe_id, resolver, self_jkt=w_tool.jkt, mode=VerificationMode.LEAF_ONLY
        )
        v_full = LeafVerifier(
            w_tool.spiffe_id,
            resolver,
            self_jkt=w_tool.jkt,
            mode=VerificationMode.LOCAL_FULL_CHAIN,
            revocation_replica=replica,
        )
        v_adaptive = LeafVerifier(
            w_tool.spiffe_id,
            resolver,
            self_jkt=w_tool.jkt,
            mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
            revocation_replica=replica,
        )

        verifier_metrics: Dict[str, Any] = {}

        # Compare LEAF_ONLY vs LOCAL_FULL_CHAIN across depths 1, 3, 5, 8
        for d in (1, 3, 5, 8):
            tok_obj, holder = tokens_by_depth[d]
            compact = tok_obj.encode_compact()
            proofs = [
                create_dpop_proof(holder, "POST", htu, compact)
                for _ in range(iterations)
            ]

            full_samples: List[float] = []
            for p in proofs:
                res = v_full.verify_request(
                    compact,
                    p,
                    "POST",
                    htu,
                    tool="get_weather",
                    arguments={"city": "New York"},
                )
                assert res.allowed
                full_samples.append(res.latency_us)
            verifier_metrics[f"LOCAL_FULL_CHAIN_depth_{d}"] = _summarize_us(full_samples)

            if d == 3:
                proofs_leaf = [
                    create_dpop_proof(holder, "POST", htu, compact)
                    for _ in range(iterations)
                ]
                leaf_samples: List[float] = []
                for p in proofs_leaf:
                    res = v_leaf.verify_request(
                        compact,
                        p,
                        "POST",
                        htu,
                        tool="get_weather",
                        arguments={"city": "New York"},
                    )
                    assert res.allowed
                    leaf_samples.append(res.latency_us)
                verifier_metrics["LEAF_ONLY_depth_3"] = _summarize_us(leaf_samples)

        # Adaptive Risk-Anchored: LOW_RISK fast path vs HIGH_RISK HTTP anchor at depth 3
        tok3, holder3 = tokens_by_depth[3]
        compact3 = tok3.encode_compact()

        low_samples: List[float] = []
        for _ in range(iterations):
            p = create_dpop_proof(holder3, "POST", htu, compact3)
            res = v_adaptive.verify_request(
                compact3,
                p,
                "POST",
                htu,
                tool="get_weather",
                arguments={"city": "New York"},
            )
            assert res.allowed
            low_samples.append(res.latency_us)
        verifier_metrics["ADAPTIVE_LOW_RISK_depth_3"] = _summarize_us(low_samples)

        high_iters = max(40, iterations // 3)
        high_samples: List[float] = []
        for _ in range(high_iters):
            p = create_dpop_proof(holder3, "POST", htu, compact3)
            res = v_adaptive.verify_request(
                compact3,
                p,
                "POST",
                htu,
                tool="execute_payment",
                arguments={"amount": 250.0},
            )
            assert res.allowed
            high_samples.append(res.latency_us)
        verifier_metrics["ADAPTIVE_HIGH_RISK_HTTP_ANCHOR_depth_3"] = _summarize_us(
            high_samples
        )

        # MultiParentToken (3-parent converging DAG at depth 2)
        w_conv = agents[8]
        mp_branches = []
        for b_idx in range(1, 4):
            ch = t_root.attenuate(
                agents[0],
                agents[b_idx].spiffe_id,
                agents[b_idx].jkt,
                base_lattice,
                hop_segment=f"B{b_idx}",
            ).attenuate(
                agents[b_idx],
                w_conv.spiffe_id,
                w_conv.jkt,
                base_lattice,
                hop_segment="C",
            )
            mp_branches.append(ch)

        mpt = MultiParentToken.assemble_and_sign(w_conv, mp_branches)
        compact_mp = mpt.encode_compact()
        token_sizes_bytes["multiparent_3_branches_depth_2"] = len(
            compact_mp.encode("ascii")
        )

        mp_samples: List[float] = []
        for _ in range(iterations):
            p = create_dpop_proof(w_conv, "POST", htu, compact_mp)
            res = v_full.verify_request(
                compact_mp,
                p,
                "POST",
                htu,
                tool="get_weather",
                arguments={"city": "New York"},
            )
            assert res.allowed
            mp_samples.append(res.latency_us)
        verifier_metrics["MULTIPARENT_3_BRANCH_DAG_depth_2"] = _summarize_us(mp_samples)
    finally:
        rev_svc.stop()

    # 4. LineagePrefixTrie lookup benchmark with 10,000 active revoked prefixes
    big_trie = LineagePrefixTrie()
    for i in range(10_000):
        big_trie.revoke_prefix(f"/rev-task-{i}/CoordA/Branch-{i % 10}", "bench", "load")

    trie_hit_us: List[float] = []
    trie_miss_us: List[float] = []
    for i in range(iterations * 5):
        t0 = time.perf_counter()
        hit = big_trie.check_lineage_path(
            f"/rev-task-{i % 10_000}/CoordA/Branch-{(i % 10_000) % 10}/LeafX/DeepY"
        )
        trie_hit_us.append((time.perf_counter() - t0) * 1_000_000.0)
        assert hit is not None

        t1 = time.perf_counter()
        miss = big_trie.check_lineage_path("/active-task-999999/CoordA/HealthyBranch/LeafZ")
        trie_miss_us.append((time.perf_counter() - t1) * 1_000_000.0)
        assert miss is None

    results = {
        "offline_attenuation_es256": _summarize_us(attenuate_samples_us),
        "wire_token_sizes_bytes": token_sizes_bytes,
        "verifier_modes_and_depths": verifier_metrics,
        "prefix_trie_10k_revocations": {
            "cascading_hit": _summarize_us(trie_hit_us),
            "unrevoked_miss": _summarize_us(trie_miss_us),
        },
    }
    return results


def main() -> None:
    results = run_benchmarks(iterations=200)
    out_path = Path(__file__).resolve().parent / "latest_benchmark.json"
    out_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print("=== LCT Cryptographic & Governance Benchmark Summary ===")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
