"""Unified Milestone-1 Test & Benchmark Runner for Lineage Capability Tree (LCT)."""

from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path

from lineage.tests.benchmark import run_benchmarks


def main() -> int:
    start = time.perf_counter()
    tests_dir = Path(__file__).resolve().parent
    repo_root = tests_dir.parent.parent

    print("=" * 76)
    print(" Lineage Capability Tree (LCT) — Full Suite Verification & Benchmark Runner")
    print("=" * 76)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(tests_dir), top_level_dir=str(repo_root))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if not result.wasSuccessful():
        print("\n[FAIL] Test suite failed!")
        return 1

    print("\n" + "=" * 76)
    print(" Running Cryptographic & Multi-Path Governance Microbenchmarks...")
    print("=" * 76)
    bench = run_benchmarks(iterations=150)
    bench_file = tests_dir / "latest_benchmark.json"
    bench_file.write_text(json.dumps(bench, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(bench, indent=2))

    elapsed = time.perf_counter() - start
    print("\n" + "=" * 76)
    print(
        f" [PASS] {result.testsRun}/{result.testsRun} tests succeeded + benchmarks saved in {elapsed:.2f}s"
    )
    print("=" * 76)
    return 0


if __name__ == "__main__":
    sys.exit(main())
