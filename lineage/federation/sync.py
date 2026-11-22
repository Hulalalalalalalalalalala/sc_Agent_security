"""Cross-Organization Federation Bundle Syncer & Autonomous Workload Bootstrapper.

Implements:
- `FederationBundleSyncer`: Pulls public-only ES256 JWKs + X.509 Root CA PEMs from
  physically independent Domain CAs (`alpha-ca`, `beta-ca`, `payment-ca`) with strict
  expected-domain pinning (`FederationSecurityError` on any domain spoofing attempt).
- `parse_domain_url_map`: Parses `"org-alpha.io=http://...,org-beta.io=http://..."`
  peer maps safely.
- `bootstrap_autonomous_workload`: Bootstraps an in-memory `WorkloadIdentity` (`JWT-SVID`)
  + `WorkloadMTLSBundle` (`X.509-SVID` + federated X.509 Root CA store) from the
  workload's own local autonomous Domain CA plus federated peer CAs.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Mapping, Optional, Sequence, Tuple

import httpx

from lineage.common.crypto import KeyPair
from lineage.common.mtls import (
    MTLSError,
    WorkloadMTLSBundle,
    X509FederationTrustStore,
)
from lineage.identity import IdentityError, SpiffeId, TrustBundleResolver, WorkloadIdentity
from lineage.k8s.bootstrap_services import (
    K8S_SA_TOKEN_PATH,
    create_ca_pop_jws,
    resolve_sa_token_path,
)


class FederationSecurityError(Exception):
    """Raised when a federated peer attempts cross-domain bundle/cert spoofing."""


def parse_domain_url_map(spec: str) -> Dict[str, str]:
    """Parse `'org-alpha.io=http://...,org-beta.io=http://...'` into `{domain: url}`."""
    mapping: Dict[str, str] = {}
    for entry in (spec or "").split(","):
        s = entry.strip()
        if not s:
            continue
        if "=" not in s:
            raise ValueError(f"Malformed domain=url entry in peer map: {s!r}")
        td, url = s.split("=", 1)
        td_clean = td.strip()
        url_clean = url.strip().rstrip("/")
        SpiffeId.parse(f"spiffe://{td_clean}/authority/ca")
        if not url_clean.startswith(("http://", "https://")):
            raise ValueError(f"Invalid peer URL for {td_clean!r}: {url_clean!r}")
        mapping[td_clean] = url_clean
    return mapping


class FederationBundleSyncer:
    """Synchronizes public JWKS + X.509 Root CAs across autonomous trust domains."""

    def __init__(
        self,
        peer_ca_urls: Mapping[str, str],
        trust_resolver: Optional[TrustBundleResolver] = None,
        x509_trust_store: Optional[X509FederationTrustStore] = None,
        timeout: float = 3.0,
    ) -> None:
        self.peer_ca_urls: Dict[str, str] = {
            str(td): str(u).rstrip("/") for td, u in peer_ca_urls.items() if str(td)
        }
        self.trust_resolver = trust_resolver or TrustBundleResolver()
        self.x509_trust_store = x509_trust_store or X509FederationTrustStore()
        self.timeout = float(timeout)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def fetch_and_verify_peer(self, expected_domain: str, ca_url: str) -> None:
        resp = httpx.get(
            f"{ca_url.rstrip('/')}/v1/federation/bundle", timeout=self.timeout
        )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise FederationSecurityError("Federation bundle response must be a JSON object")

        actual_td = str(data.get("trust_domain") or "")
        if actual_td != expected_domain:
            raise FederationSecurityError(
                f"Federation bundle spoofing blocked from {ca_url!r}: "
                f"expected trust_domain={expected_domain!r}, got {actual_td!r}"
            )
        try:
            self.trust_resolver.register_bundle(data)
            if "x509_root_pem" in data and data["x509_root_pem"]:
                self.x509_trust_store.register_domain_root_pem(
                    expected_domain, str(data["x509_root_pem"])
                )
        except (IdentityError, MTLSError) as exc:
            raise FederationSecurityError(
                f"Invalid federation bundle from {expected_domain!r}: {exc}"
            ) from exc

    def sync_all(self, require_all: bool = True, max_wait_sec: float = 45.0) -> None:
        """Synchronize all configured peer domain bundles (retrying during K8s startup)."""
        deadline = time.time() + max(0.1, float(max_wait_sec))
        pending = dict(self.peer_ca_urls)
        last_err: Optional[Exception] = None
        while pending:
            for td, url in list(pending.items()):
                try:
                    self.fetch_and_verify_peer(td, url)
                    pending.pop(td, None)
                except FederationSecurityError:
                    # Cryptographic/domain spoofing fails closed immediately!
                    raise
                except Exception as exc:
                    last_err = exc
            if not pending:
                return
            if not require_all or time.time() >= deadline:
                break
            time.sleep(0.4)

        if require_all and pending:
            raise RuntimeError(
                f"Timed out syncing federation bundles for {sorted(pending.keys())}: {last_err}"
            )

    def start_background_refresh(self, interval_sec: float = 10.0) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()

        def _loop() -> None:
            while not self._stop.is_set():
                try:
                    self.sync_all(require_all=False, max_wait_sec=2.0)
                except Exception:
                    pass
                self._stop.wait(interval_sec)

        self._thread = threading.Thread(
            target=_loop, name="federation-bundle-sync", daemon=True
        )
        self._thread.start()

    def stop_background_refresh(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


def bootstrap_autonomous_workload(
    local_ca_url: str,
    peer_ca_urls: Mapping[str, str],
    sa_token_path: str = K8S_SA_TOKEN_PATH,
    max_wait_sec: float = 45.0,
    require_all_peers: bool = True,
    seed_bundles: Optional[Sequence[Mapping[str, object]]] = None,
    peer_timeout: float = 3.0,
) -> Tuple[WorkloadIdentity, TrustBundleResolver, WorkloadMTLSBundle, FederationBundleSyncer]:
    """Generate RAM-only ES256 keypair, obtain `JWT-SVID` + `X.509-SVID` from local CA,
    and synchronize federated JWKS + X.509 Root CAs across peer domains.
    """
    resolved_tok_path = resolve_sa_token_path(sa_token_path)
    keypair = KeyPair.generate("ES256")
    deadline = time.time() + max_wait_sec
    last_err: Optional[Exception] = None
    ca_data: Optional[Dict[str, object]] = None

    while time.time() < deadline:
        try:
            with open(resolved_tok_path, "r", encoding="utf-8") as fh:
                sa_jwt = fh.read().strip()
            pop_jws = create_ca_pop_jws(keypair, sa_jwt)
            resp = httpx.post(
                f"{local_ca_url.rstrip('/')}/v1/ca/issue-workload",
                json={
                    "public_jwk": keypair.public_jwk(),
                    "pop_jws": pop_jws,
                    "ttl_seconds": 1800.0,
                },
                headers={"Authorization": f"Bearer {sa_jwt}"},
                timeout=5.0,
            )
            if resp.status_code == 200:
                ca_data = resp.json()
                break
            last_err = RuntimeError(f"Local CA HTTP {resp.status_code}: {resp.text}")
        except Exception as exc:
            last_err = exc
        time.sleep(0.4)

    if ca_data is None:
        raise RuntimeError(
            f"Failed to bootstrap workload identity from {local_ca_url}: {last_err}"
        )

    syncer = FederationBundleSyncer(peer_ca_urls=peer_ca_urls, timeout=peer_timeout)
    # Seed own domain bundle immediately, plus any pre-cached public peer bundles
    own_td = str(ca_data["trust_domain"])
    own_bundle = ca_data.get("bundle")
    if isinstance(own_bundle, Mapping):
        syncer.trust_resolver.register_bundle(own_bundle)
        if own_bundle.get("x509_root_pem"):
            syncer.x509_trust_store.register_domain_root_pem(
                own_td, str(own_bundle["x509_root_pem"])
            )
    if seed_bundles:
        for sb in seed_bundles:
            if isinstance(sb, Mapping) and sb.get("trust_domain"):
                sb_td = str(sb["trust_domain"])
                syncer.trust_resolver.register_bundle(sb)
                if sb.get("x509_root_pem"):
                    syncer.x509_trust_store.register_domain_root_pem(
                        sb_td, str(sb["x509_root_pem"])
                    )
    syncer.sync_all(require_all=require_all_peers, max_wait_sec=max_wait_sec)
    syncer.start_background_refresh(interval_sec=15.0)

    identity = WorkloadIdentity(
        spiffe_id=str(ca_data["spiffe_id"]),
        trust_domain=own_td,
        keypair=keypair,
        workload_svid=str(ca_data["workload_svid"]),
        issued_at=float(ca_data["issued_at"]),
        expires_at=float(ca_data["expires_at"]),
    )
    mtls_bundle = WorkloadMTLSBundle(
        spiffe_id=identity.spiffe_id,
        keypair=keypair,
        leaf_cert_pem=str(ca_data["x509_leaf_pem"]),
        trust_store=syncer.x509_trust_store,
    )
    return identity, syncer.trust_resolver, mtls_bundle, syncer
