"""20+ Node Distributed Peer-to-Peer Scale & Decentralized Audit Benchmark Suite."""

from __future__ import annotations

from typing import Any

__all__ = [
    "format_scale_benchmark_markdown",
    "run_distributed_scale_benchmark",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from lineage.scale import distributed_benchmark as _mod

        return getattr(_mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
