"""Three-Layer Fault Detector (Crash, Timeout, Policy/Byzantine Circuit Breaker)."""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional

import httpx

from lineage.resilience.receipts import FailureEvidence, FaultType


class ThreeLayerFaultDetector:
    """Thread-safe detector classifying network, latency, and Byzantine/policy faults."""

    def __init__(
        self,
        policy_breaker_threshold: int = 2,
        cooldown_seconds: float = 300.0,
    ) -> None:
        if policy_breaker_threshold < 1:
            raise ValueError("policy_breaker_threshold must be >= 1")
        self.policy_breaker_threshold = int(policy_breaker_threshold)
        self.cooldown_seconds = float(cooldown_seconds)
        self._lock = threading.Lock()
        self._policy_counts: Dict[str, int] = {}
        self._tripped_until: Dict[str, float] = {}
        self._last_evidence: Dict[str, FailureEvidence] = {}

    def is_circuit_open(self, spiffe_id: str, now: Optional[float] = None) -> bool:
        ts = time.time() if now is None else float(now)
        with self._lock:
            until = self._tripped_until.get(spiffe_id, 0.0)
            return until > ts

    def get_last_evidence(self, spiffe_id: str) -> Optional[FailureEvidence]:
        with self._lock:
            return self._last_evidence.get(spiffe_id)

    def record_success(self, spiffe_id: str) -> None:
        with self._lock:
            self._policy_counts.pop(spiffe_id, None)

    def classify_exception(
        self,
        spiffe_id: str,
        endpoint: str,
        exc: BaseException,
        attempt_count: int = 1,
        now: Optional[float] = None,
    ) -> FailureEvidence:
        ts = time.time() if now is None else float(now)
        if isinstance(exc, (httpx.TimeoutException, TimeoutError)):
            ftype = FaultType.TIMEOUT
        else:
            ftype = FaultType.CRASH

        ev = FailureEvidence(
            failed_spiffe_id=spiffe_id,
            failed_endpoint=endpoint,
            fault_type=ftype,
            error_detail=f"{type(exc).__name__}: {exc}",
            attempt_count=attempt_count,
            observed_at=ts,
        )
        with self._lock:
            self._last_evidence[spiffe_id] = ev
        return ev

    def classify_http_failure(
        self,
        spiffe_id: str,
        endpoint: str,
        status_code: int,
        body_text: str,
        attempt_count: int = 1,
        now: Optional[float] = None,
    ) -> Optional[FailureEvidence]:
        """Classify non-2xx HTTP responses into Crash, Timeout, or Policy Circuit Breaker."""
        ts = time.time() if now is None else float(now)
        if 200 <= status_code < 300:
            self.record_success(spiffe_id)
            return None

        if status_code in (408, 504):
            ev = FailureEvidence(
                failed_spiffe_id=spiffe_id,
                failed_endpoint=endpoint,
                fault_type=FaultType.TIMEOUT,
                error_detail=f"HTTP {status_code}: {body_text[:200]}",
                attempt_count=attempt_count,
                observed_at=ts,
            )
            with self._lock:
                self._last_evidence[spiffe_id] = ev
            return ev

        if status_code in (500, 502, 503):
            ev = FailureEvidence(
                failed_spiffe_id=spiffe_id,
                failed_endpoint=endpoint,
                fault_type=FaultType.CRASH,
                error_detail=f"HTTP {status_code}: {body_text[:200]}",
                attempt_count=attempt_count,
                observed_at=ts,
            )
            with self._lock:
                self._last_evidence[spiffe_id] = ev
            return ev

        if status_code in (401, 403):
            return self.record_policy_violation(
                spiffe_id=spiffe_id,
                endpoint=endpoint,
                detail=f"HTTP {status_code}: {body_text[:200]}",
                now=ts,
            )

        return FailureEvidence(
            failed_spiffe_id=spiffe_id,
            failed_endpoint=endpoint,
            fault_type=FaultType.CRASH,
            error_detail=f"Unexpected HTTP {status_code}: {body_text[:200]}",
            attempt_count=attempt_count,
            observed_at=ts,
        )

    def record_policy_violation(
        self,
        spiffe_id: str,
        endpoint: str,
        detail: str,
        now: Optional[float] = None,
    ) -> Optional[FailureEvidence]:
        """Increment consecutive policy violation counter; return FailureEvidence when tripped."""
        ts = time.time() if now is None else float(now)
        with self._lock:
            cnt = self._policy_counts.get(spiffe_id, 0) + 1
            self._policy_counts[spiffe_id] = cnt
            if cnt >= self.policy_breaker_threshold:
                self._tripped_until[spiffe_id] = ts + self.cooldown_seconds
                ev = FailureEvidence(
                    failed_spiffe_id=spiffe_id,
                    failed_endpoint=endpoint,
                    fault_type=FaultType.POLICY_BYZANTINE,
                    error_detail=f"Policy circuit breaker tripped ({cnt}/{self.policy_breaker_threshold}): {detail}",
                    attempt_count=cnt,
                    observed_at=ts,
                )
                self._last_evidence[spiffe_id] = ev
                return ev
            return None
