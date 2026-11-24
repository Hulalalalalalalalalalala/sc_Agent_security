"""Cross-Organization Federation Bundle Syncer, Trust Anchor Enforcement & SVID Renewer.

Implements:
- `FederationBundleSyncer`: Pulls public-only ES256 JWKs + X.509 Root CA PEMs from
  physically independent Domain CAs (`alpha-ca`, `beta-ca`, `payment-ca`, plus keyless
  `org-audit.io`) with strict expected-domain pinning, SSH-style SHA-256 trust anchor
  verification (`ConfigMap` hot-reload + fail-closed eviction), and startup-order
  independence (`is_ready()`).
- `WorkloadIdentityRenewer`: Background SVID & X.509 leaf certificate auto-renewer at
  ~50% of remaining lifetime, re-reading kubelet-rotated projected ServiceAccount tokens,
  performing fresh Proof-of-Possession, atomically swapping `WorkloadIdentity` +
  `WorkloadMTLSBundle` server/client `SSLContext`s, and triggering monotonic `AgentCard`
  re-registration callbacks.
- `bootstrap_autonomous_workload`: Bootstraps an in-memory `WorkloadIdentity` (`JWT-SVID`)
  + `WorkloadMTLSBundle` (`X.509-SVID` + federated X.509 Root CA store) with optional
  order-independent peer sync and background auto-renewal.
"""

from __future__ import annotations

import ssl
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import httpx

from lineage.common.crypto import CryptoError, KeyPair
from lineage.common.mtls import (
    MTLSError,
    WorkloadMTLSBundle,
    X509FederationTrustStore,
)
from lineage.federation.anchors import (
    TrustAnchorPinError,
    TrustAnchorPinStore,
    compute_bundle_trust_anchor,
    extract_canonical_bundle_root_pem,
)
from lineage.federation.locators import (
    MAX_DESCRIPTORS_PER_MESSAGE,
    MAX_DESCRIPTOR_HTTP_BYTES,
    DomainDescriptorStore,
    SeedEndpointStore,
    ServiceLocator,
    SignedDomainDescriptor,
    seed_candidate_descriptor_urls,
)
from lineage.identity import IdentityError, SpiffeId, TrustBundleResolver, WorkloadIdentity
from lineage.k8s.bootstrap_services import (
    K8S_SA_TOKEN_PATH,
    create_ca_pop_jws,
    resolve_sa_token_path,
)


class FederationSecurityError(Exception):
    """Raised when a federated peer fails domain or cryptographic trust-anchor verification."""


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
    """Synchronizes public JWKS + X.509 Root CAs + Signed Domain Descriptors across trust domains."""

    def __init__(
        self,
        peer_ca_urls: Optional[Mapping[str, str]] = None,
        trust_resolver: Optional[TrustBundleResolver] = None,
        x509_trust_store: Optional[X509FederationTrustStore] = None,
        timeout: float = 3.0,
        anchor_store: Optional[TrustAnchorPinStore] = None,
        require_pinned_anchors: bool = False,
        audit_ca_url: Optional[str] = None,
        local_trust_domain: Optional[str] = None,
        seed_store: Optional[SeedEndpointStore] = None,
        descriptor_store: Optional[DomainDescriptorStore] = None,
        local_ca_url: Optional[str] = None,
        sa_token_path: Optional[str] = None,
        persisted_descriptors_file: Optional[str] = None,
    ) -> None:
        self.peer_ca_urls: Dict[str, str] = {
            str(td): str(u).rstrip("/")
            for td, u in (peer_ca_urls or {}).items()
            if str(td)
        }
        self.audit_ca_url: Optional[str] = (
            audit_ca_url.strip().rstrip("/") if audit_ca_url and audit_ca_url.strip() else None
        )
        self.local_trust_domain: Optional[str] = (
            local_trust_domain.strip().lower() if local_trust_domain else None
        )
        self.seed_store = seed_store
        self.descriptor_store = descriptor_store
        self.local_ca_url: Optional[str] = (
            local_ca_url.strip().rstrip("/") if local_ca_url and local_ca_url.strip() else None
        )
        self.sa_token_path = sa_token_path
        self.persisted_descriptors_file = persisted_descriptors_file
        self.trust_resolver = trust_resolver or TrustBundleResolver()
        self.x509_trust_store = x509_trust_store or X509FederationTrustStore()
        self.timeout = float(timeout)
        self.anchor_store = anchor_store
        self.require_pinned_anchors = bool(require_pinned_anchors)
        self.identity_renewer: Optional["WorkloadIdentityRenewer"] = None
        self._state_lock = threading.RLock()
        self._verified_domains: Dict[str, str] = {}
        self._last_errors: Dict[str, str] = {}
        self._rejected_bundle_counts: Dict[str, int] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        if self.persisted_descriptors_file and self.descriptor_store is not None:
            self.descriptor_store.load_persisted_file(self.persisted_descriptors_file)
            for desc in self.descriptor_store.all_descriptors().values():
                try:
                    self.apply_verified_descriptor(desc)
                except Exception:
                    continue

    def _all_target_urls(self) -> Dict[str, str]:
        targets = dict(self.peer_ca_urls)
        if self.audit_ca_url:
            targets.setdefault("org-audit.io", self.audit_ca_url)
        return targets

    def _required_peer_domains_from_pins(self) -> List[str]:
        if self.anchor_store is None:
            return []
        self.anchor_store.refresh_if_changed()
        pins = self.anchor_store.all_pins()
        return sorted(
            td for td in pins.keys() if not self.local_trust_domain or td != self.local_trust_domain
        )

    def _evict_peer_domain(self, domain: str) -> None:
        self.trust_resolver.evict_domain(domain)
        self.x509_trust_store.evict_domain(domain)
        with self._state_lock:
            self._verified_domains.pop(domain, None)

    def apply_verified_descriptor(self, desc: SignedDomainDescriptor) -> None:
        """Import X.509 Root CA + JWKS from an already pin- and signature-verified descriptor."""
        td = desc.trust_domain
        root_pem = extract_canonical_bundle_root_pem(desc.bundle)
        self.x509_trust_store.register_domain_root_pem(td, root_pem)
        keys_list = desc.bundle.get("keys") or []
        if keys_list:
            self.trust_resolver.register_bundle(desc.bundle)
        if not self.local_trust_domain or td != self.local_trust_domain:
            with self._state_lock:
                self._verified_domains[td] = desc.trust_anchor
                self._last_errors.pop(td, None)

    def _push_learned_descriptors_to_local_ca(
        self, learned: Sequence[SignedDomainDescriptor]
    ) -> None:
        if not learned or not self.local_ca_url or not self.sa_token_path:
            return
        try:
            tok_file = resolve_sa_token_path(self.sa_token_path)
            with open(tok_file, "r", encoding="utf-8") as fh:
                sa_jwt = fh.read().strip()
            httpx.post(
                f"{self.local_ca_url}/v1/ca/learn-descriptors",
                json={"descriptors": [d.to_dict() for d in learned]},
                headers={"Authorization": f"Bearer {sa_jwt}"},
                timeout=2.5,
                trust_env=False,
            )
        except Exception:
            pass

    @staticmethod
    def _enforce_descriptor_response_limit(resp: httpx.Response) -> None:
        cl = resp.headers.get("content-length")
        if cl:
            try:
                if int(cl) > MAX_DESCRIPTOR_HTTP_BYTES:
                    raise FederationSecurityError(
                        f"Descriptor HTTP Content-Length {cl} exceeds {MAX_DESCRIPTOR_HTTP_BYTES} bytes"
                    )
            except ValueError:
                pass

    def _ingest_descriptor_list_payload(
        self, payload: Any, learned_peers: List[SignedDomainDescriptor]
    ) -> None:
        if self.descriptor_store is None or not isinstance(payload, Mapping):
            return
        raw_items = payload.get("descriptors")
        if not isinstance(raw_items, list) or len(raw_items) > MAX_DESCRIPTORS_PER_MESSAGE:
            return
        for raw_d in raw_items:
            if not isinstance(raw_d, Mapping):
                continue
            try:
                updated, desc = self.descriptor_store.ingest_raw_descriptor(raw_d)
                self.apply_verified_descriptor(desc)
                if updated and (
                    not self.local_trust_domain
                    or desc.trust_domain != self.local_trust_domain
                ):
                    learned_peers.append(desc)
            except Exception:
                continue

    def sync_descriptors_from_seeds_and_peers(self) -> int:
        """Bidirectionally announce & pull `/v1/federation/descriptors` across seeds & verified peers."""
        if self.descriptor_store is None:
            return 0
        self.reconcile_anchor_evictions()
        learned_peers: List[SignedDomainDescriptor] = []

        # 1. Pull own `local_ca_url` FIRST so our local signed descriptor (and any descriptors
        #    announced directly to our local CA) are present in `self.descriptor_store`.
        local_ca_desc_url = (
            f"{self.local_ca_url.rstrip('/')}/v1/federation/descriptors"
            if self.local_ca_url
            else None
        )
        if local_ca_desc_url:
            try:
                with httpx.Client(
                    verify=True,
                    timeout=self.timeout,
                    follow_redirects=False,
                    trust_env=False,
                    event_hooks={"response": [self._enforce_descriptor_response_limit]},
                ) as local_cli:
                    r_loc = local_cli.get(local_ca_desc_url)
                if r_loc.status_code == 200 and len(r_loc.content) <= MAX_DESCRIPTOR_HTTP_BYTES:
                    self._ingest_descriptor_list_payload(r_loc.json(), learned_peers)
            except Exception:
                pass

        # 2. Collect remote seed & verified peer descriptor endpoints
        candidate_targets: List[Tuple[str, Optional[str], Optional[str]]] = []
        if self.seed_store is not None:
            for s in self.seed_store.list_seeds():
                for u in seed_candidate_descriptor_urls(s):
                    if u != local_ca_desc_url and all(
                        existing_u != u for existing_u, _, _ in candidate_targets
                    ):
                        candidate_targets.append((u, None, None))
        for peer_td, locs in self.descriptor_store.peer_locators(
            "ca_bundle", exclude_domain=self.local_trust_domain
        ).items():
            for loc in locs:
                u = f"{loc.origin_url}/v1/federation/descriptors"
                if u != local_ca_desc_url and all(
                    existing_u != u for existing_u, _, _ in candidate_targets
                ):
                    candidate_targets.append((u, peer_td, loc.spiffe_id))

        # 3. For each remote endpoint, push our bounded verified gossip set AND pull theirs
        for url, peer_td, loc_spiffe in candidate_targets:
            verify_kw: Any = True
            if url.startswith("https://"):
                if (
                    peer_td
                    and loc_spiffe
                    and self.x509_trust_store.has_domain(peer_td)
                ):
                    try:
                        verify_kw = self.x509_trust_store.build_server_verify_ssl_context(
                            expected_trust_domain=peer_td,
                            check_hostname=False,
                            expected_spiffe_id=loc_spiffe,
                        )
                    except MTLSError:
                        continue
                else:
                    continue
            try:
                with httpx.Client(
                    verify=verify_kw,
                    timeout=self.timeout,
                    follow_redirects=False,
                    trust_env=False,
                    event_hooks={"response": [self._enforce_descriptor_response_limit]},
                ) as client:
                    out_gossip = self.descriptor_store.export_gossip_payload()
                    out_descs = out_gossip.get("descriptors") or []
                    if out_descs:
                        try:
                            client.post(
                                url,
                                json={
                                    "trust_domain": self.local_trust_domain,
                                    "descriptors": out_descs[:MAX_DESCRIPTORS_PER_MESSAGE],
                                },
                            )
                        except Exception:
                            pass
                    resp = client.get(url)
                if (
                    resp.status_code != 200
                    or len(resp.content) > MAX_DESCRIPTOR_HTTP_BYTES
                ):
                    continue
                payload = resp.json()
            except Exception:
                continue

            self._ingest_descriptor_list_payload(payload, learned_peers)

        if learned_peers:
            self._push_learned_descriptors_to_local_ca(learned_peers)
        return len(learned_peers)

    def _has_active_verified_pin(self, domain: str) -> bool:
        """Return True iff `domain` is already verified against the current local pin."""
        with self._state_lock:
            cur_verified = self._verified_domains.get(domain)
        if cur_verified is None:
            return False
        if self.anchor_store is not None:
            cur_pin = self.anchor_store.get_pin(domain)
            if cur_pin is not None:
                return cur_verified == cur_pin
            return not self.require_pinned_anchors
        return True

    def _reject_remote_candidate(self, domain: str, msg: str) -> None:
        """Record a rejected remote bundle without evicting an already pin-verified peer."""
        if not self._has_active_verified_pin(domain):
            self._evict_peer_domain(domain)
        with self._state_lock:
            self._rejected_bundle_counts[domain] = (
                self._rejected_bundle_counts.get(domain, 0) + 1
            )
            self._last_errors[domain] = msg

    def reconcile_anchor_evictions(self) -> bool:
        """Hot-reload `TrustAnchorPinStore` and evict any domain whose pin was removed or altered."""
        desc_evicted: List[str] = []
        if self.descriptor_store is not None:
            desc_evicted = self.descriptor_store.reconcile_with_pins()
            for td in desc_evicted:
                self._evict_peer_domain(td)
        if self.anchor_store is None:
            return bool(desc_evicted)
        changed = self.anchor_store.refresh_if_changed()
        with self._state_lock:
            verified_snapshot = dict(self._verified_domains)
        evicted_any = bool(desc_evicted)
        for td, prev_anchor in verified_snapshot.items():
            cur_pin = self.anchor_store.get_pin(td)
            if self.require_pinned_anchors and cur_pin is None:
                self._evict_peer_domain(td)
                with self._state_lock:
                    self._last_errors[td] = (
                        f"Missing pinned trust anchor for {td!r} in lct-trust-anchors"
                    )
                evicted_any = True
            elif cur_pin is not None and cur_pin != prev_anchor:
                self._evict_peer_domain(td)
                with self._state_lock:
                    self._last_errors[td] = (
                        f"Trust anchor pin changed for {td!r}; awaiting re-verification"
                    )
                evicted_any = True
        return changed or evicted_any

    def audit_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Build a TLS 1.3 client `SSLContext` pinned to `org-audit.io` once verified."""
        self.reconcile_anchor_evictions()
        if not self.x509_trust_store.has_domain("org-audit.io"):
            return None
        try:
            return self.x509_trust_store.build_server_verify_ssl_context(
                expected_trust_domain="org-audit.io",
                check_hostname=True,
            )
        except MTLSError:
            return None

    def audit_locators(self) -> Tuple[ServiceLocator, ...]:
        """Return signed `audit_collector` locators for `org-audit.io` from `descriptor_store`."""
        if self.descriptor_store is None:
            return ()
        return self.descriptor_store.get_locators("org-audit.io", "audit_collector")

    def audit_ssl_context_for_locator(self, loc: ServiceLocator) -> Optional[ssl.SSLContext]:
        """Build SPIFFE-pinned (`check_hostname=False`, zero IP-SNI) TLS 1.3 context for an audit locator."""
        self.reconcile_anchor_evictions()
        if not self.x509_trust_store.has_domain("org-audit.io") or not loc.spiffe_id:
            return None
        try:
            return self.x509_trust_store.build_server_verify_ssl_context(
                expected_trust_domain="org-audit.io",
                check_hostname=False,
                expected_spiffe_id=loc.spiffe_id,
            )
        except MTLSError:
            return None

    def fetch_and_verify_peer(self, expected_domain: str, ca_url: str) -> str:
        """Fetch, pin-verify, and import a single peer domain's public bundle."""
        self.reconcile_anchor_evictions()
        clean_url = ca_url.rstrip("/")

        if self.require_pinned_anchors:
            if self.anchor_store is None or self.anchor_store.get_pin(expected_domain) is None:
                self._evict_peer_domain(expected_domain)
                msg = (
                    f"Missing required trust anchor pin for {expected_domain!r}. "
                    f"Pin via: python3 lineage/multihost/lct_multihost_cli.py trust add {expected_domain} <anchor>"
                )
                with self._state_lock:
                    self._last_errors[expected_domain] = msg
                raise FederationSecurityError(msg)

        verify_arg: Any = True
        need_post_handshake_probe = False
        if clean_url.startswith("https://"):
            if self.x509_trust_store.has_domain(expected_domain):
                verify_arg = self.x509_trust_store.build_server_verify_ssl_context(
                    expected_trust_domain=expected_domain,
                    check_hostname=True,
                )
            else:
                # Candidate bundle fetch ONLY; immediately verified against cryptographic
                # SPKI pin + TLS 1.3 server certificate handshake before activation!
                verify_arg = False
                need_post_handshake_probe = True

        with httpx.Client(verify=verify_arg, timeout=self.timeout) as client:
            resp = client.get(f"{clean_url}/v1/federation/bundle")
        resp.raise_for_status()
        try:
            data = resp.json()
        except Exception as exc:
            msg = f"Malformed JSON in federation bundle from {clean_url!r}: {exc}"
            self._reject_remote_candidate(expected_domain, msg)
            raise FederationSecurityError(msg) from exc

        return self._verify_and_apply_bundle(
            expected_domain=expected_domain,
            data=data,
            clean_url=clean_url,
            need_post_handshake_probe=need_post_handshake_probe,
        )

    def _verify_and_apply_bundle(
        self,
        expected_domain: str,
        data: Mapping[str, Any],
        clean_url: str = "",
        need_post_handshake_probe: bool = False,
    ) -> str:
        """Cryptographically verify a candidate bundle before mutating live RAM trust stores."""
        if not isinstance(data, Mapping):
            msg = "Federation bundle response must be a JSON object"
            self._reject_remote_candidate(expected_domain, msg)
            raise FederationSecurityError(msg)

        actual_td = str(data.get("trust_domain") or "")
        if actual_td != expected_domain:
            msg = (
                f"Federation bundle spoofing blocked from {clean_url or expected_domain!r}: "
                f"expected trust_domain={expected_domain!r}, got {actual_td!r}"
            )
            self._reject_remote_candidate(expected_domain, msg)
            raise FederationSecurityError(msg)

        is_keyless = expected_domain == "org-audit.io" and not (data.get("keys") or [])
        try:
            canonical_root_pem = extract_canonical_bundle_root_pem(data)
            if self.anchor_store is not None:
                computed_anchor = self.anchor_store.verify_bundle(
                    expected_domain=expected_domain,
                    bundle=data,
                    require_pin=self.require_pinned_anchors,
                    allow_keyless_jwks=is_keyless,
                )
            else:
                computed_anchor = compute_bundle_trust_anchor(
                    data, allow_keyless_jwks=is_keyless
                )
        except (TrustAnchorPinError, CryptoError, MTLSError) as exc:
            msg = str(exc)
            self._reject_remote_candidate(expected_domain, msg)
            raise FederationSecurityError(msg) from exc

        # Pre-validate X.509 certificate extensions + JWKS on isolated scratch stores
        # BEFORE mutating live RAM stores so malformed candidates never corrupt verified peers!
        try:
            scratch_x509 = X509FederationTrustStore()
            for existing_td, existing_pem in self.x509_trust_store.export_domain_pems().items():
                if existing_td != expected_domain:
                    scratch_x509.register_domain_root_pem(existing_td, existing_pem)
            scratch_x509.register_domain_root_pem(expected_domain, canonical_root_pem)

            if not is_keyless:
                scratch_jwk = TrustBundleResolver()
                scratch_jwk.register_bundle(data)

            if need_post_handshake_probe and clean_url:
                probe_ctx = scratch_x509.build_server_verify_ssl_context(
                    expected_trust_domain=expected_domain,
                    check_hostname=True,
                )
                with httpx.Client(verify=probe_ctx, timeout=self.timeout) as probe_cli:
                    pr = probe_cli.get(f"{clean_url}/healthz")
                    pr.raise_for_status()

            if not is_keyless:
                self.trust_resolver.register_bundle(data)
            self.x509_trust_store.register_domain_root_pem(
                expected_domain, canonical_root_pem
            )
        except Exception as exc:
            msg = f"Invalid federation bundle or TLS leaf proof from {expected_domain!r}: {exc}"
            self._reject_remote_candidate(expected_domain, msg)
            if isinstance(exc, (IdentityError, MTLSError, CryptoError, TrustAnchorPinError)):
                raise FederationSecurityError(msg) from exc
            raise FederationSecurityError(msg) from exc

        with self._state_lock:
            self._verified_domains[expected_domain] = computed_anchor
            self._last_errors.pop(expected_domain, None)
        return computed_anchor

    def is_ready(self) -> Tuple[bool, Dict[str, Any]]:
        """Return `(ready_bool, diagnostic_dict)` for Kubernetes `/readyz` probes."""
        self.reconcile_anchor_evictions()
        targets = self._all_target_urls()
        descriptor_mode = (not targets) and (self.descriptor_store is not None)
        if descriptor_mode:
            req_peers = self._required_peer_domains_from_pins()
            awaiting_pins = bool(self.require_pinned_anchors and not req_peers)
            with self._state_lock:
                verified = dict(self._verified_domains)
                rejected_counts = dict(self._rejected_bundle_counts)
            missing: List[str] = []
            for td in req_peers:
                if td not in verified or (
                    self.descriptor_store is not None
                    and self.descriptor_store.get_descriptor(td) is None
                ):
                    missing.append(td)
            desc_diag = (
                self.descriptor_store.diagnostics()
                if self.descriptor_store is not None
                else {}
            )
            ready_ok = (not awaiting_pins) and (len(missing) == 0)
            return (
                ready_ok,
                {
                    "mode": "identity_descriptors",
                    "awaiting_peer_trust_pins": awaiting_pins,
                    "missing_domains": missing,
                    "verified_domains": verified,
                    "errors": desc_diag.get("last_descriptor_errors", {}),
                    "rejected_bundle_counts": rejected_counts,
                    "rejected_descriptor_counts": desc_diag.get(
                        "rejected_descriptor_counts", {}
                    ),
                    "ignored_unpinned_domains": desc_diag.get(
                        "ignored_unpinned_domains", []
                    ),
                    "trust_store_version": self.x509_trust_store.version,
                },
            )

        with self._state_lock:
            missing = sorted(td for td in targets if td not in self._verified_domains)
            verified = dict(self._verified_domains)
            # Only expose blocking startup errors for unverified domains; keep rejected spoof telemetry separate!
            errors = {
                td: err
                for td, err in self._last_errors.items()
                if td in targets and td not in self._verified_domains
            }
            rejected_counts = dict(self._rejected_bundle_counts)
        return (
            len(missing) == 0,
            {
                "missing_domains": missing,
                "verified_domains": verified,
                "errors": errors,
                "rejected_bundle_counts": rejected_counts,
                "trust_store_version": self.x509_trust_store.version,
            },
        )

    def sync_all(self, require_all: bool = True, max_wait_sec: float = 45.0) -> None:
        """Synchronize all configured peer domain bundles & signed descriptors."""
        self.reconcile_anchor_evictions()
        deadline = time.time() + max(0.1, float(max_wait_sec))
        pending = self._all_target_urls()
        if not pending and self.descriptor_store is not None:
            while True:
                self.sync_descriptors_from_seeds_and_peers()
                ready_ok, diag = self.is_ready()
                if ready_ok:
                    return
                if not require_all or time.time() >= deadline:
                    if require_all:
                        raise RuntimeError(
                            f"Timed out syncing signed domain descriptors: {diag}"
                        )
                    return
                time.sleep(0.4)

        last_err: Optional[Exception] = None
        while pending:
            if self.descriptor_store is not None:
                self.sync_descriptors_from_seeds_and_peers()
            for td, url in list(pending.items()):
                try:
                    self.fetch_and_verify_peer(td, url)
                    pending.pop(td, None)
                except FederationSecurityError as exc:
                    last_err = exc
                    if require_all:
                        # Cryptographic/domain spoofing or pin mismatch fails closed immediately!
                        raise
                except Exception as exc:
                    last_err = exc
                    with self._state_lock:
                        self._last_errors[td] = f"{type(exc).__name__}: {exc}"
            if not pending:
                return
            if not require_all or time.time() >= deadline:
                break
            time.sleep(0.4)

        if require_all and pending:
            raise RuntimeError(
                f"Timed out syncing federation bundles for {sorted(pending.keys())}: {last_err}"
            )

    def start_background_refresh(self, interval_sec: float = 2.0) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()

        def _loop() -> None:
            backoff = 0.5
            while not self._stop.is_set():
                try:
                    self.sync_all(require_all=False, max_wait_sec=1.5)
                    ready, _ = self.is_ready()
                    wait_s = interval_sec if ready else min(interval_sec, backoff)
                    backoff = 0.5 if ready else min(interval_sec, backoff * 1.5)
                except Exception:
                    wait_s = min(interval_sec, backoff)
                    backoff = min(interval_sec, backoff * 1.5)
                self._stop.wait(wait_s)

        self._thread = threading.Thread(
            target=_loop, name="federation-bundle-sync", daemon=True
        )
        self._thread.start()

    def stop_background_refresh(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self.identity_renewer is not None:
            self.identity_renewer.stop()


class WorkloadIdentityRenewer:
    """Automatic background SVID & X.509 leaf certificate renewer at ~50% remaining TTL."""

    def __init__(
        self,
        local_ca_url: str,
        identity: WorkloadIdentity,
        mtls_bundle: Optional[WorkloadMTLSBundle] = None,
        trust_resolver: Optional[TrustBundleResolver] = None,
        x509_trust_store: Optional[X509FederationTrustStore] = None,
        sa_token_path: str = K8S_SA_TOKEN_PATH,
        ttl_seconds: float = 1800.0,
        rotate_keypair: bool = False,
        on_renewed: Optional[Callable[[WorkloadIdentity, Optional[WorkloadMTLSBundle]], None]] = None,
        check_interval_sec: Optional[float] = None,
    ) -> None:
        self.local_ca_url = local_ca_url.rstrip("/")
        self.identity = identity
        self.mtls_bundle = mtls_bundle
        self.trust_resolver = trust_resolver
        self.x509_trust_store = x509_trust_store
        self.sa_token_path = sa_token_path
        self.ttl_seconds = max(4.0, float(ttl_seconds))
        self.rotate_keypair = bool(rotate_keypair)
        self._callbacks: List[Callable[[WorkloadIdentity, Optional[WorkloadMTLSBundle]], None]] = []
        if on_renewed is not None:
            self._callbacks.append(on_renewed)
        self.check_interval_sec = (
            float(check_interval_sec)
            if check_interval_sec is not None
            else max(0.25, min(10.0, self.ttl_seconds * 0.15))
        )
        self._lock = threading.Lock()
        self.renewal_count: int = 0
        self.last_error: Optional[str] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def add_callback(
        self, cb: Callable[[WorkloadIdentity, Optional[WorkloadMTLSBundle]], None]
    ) -> None:
        with self._lock:
            self._callbacks.append(cb)

    def should_renew(self, now: Optional[float] = None) -> bool:
        ts = time.time() if now is None else float(now)
        lifetime = max(1.0, self.identity.expires_at - self.identity.issued_at)
        remaining = self.identity.expires_at - ts
        return remaining <= (0.5 * lifetime)

    def renew_once(self) -> Dict[str, Any]:
        """Perform an immediate CA PoP renewal, atomically swapping SVID & mTLS leaf cert."""
        resolved_tok_path = resolve_sa_token_path(self.sa_token_path)
        with open(resolved_tok_path, "r", encoding="utf-8") as fh:
            sa_jwt = fh.read().strip()
        next_keypair = (
            KeyPair.generate(self.identity.keypair.alg)
            if self.rotate_keypair
            else self.identity.keypair
        )
        pop_jws = create_ca_pop_jws(next_keypair, sa_jwt)
        resp = httpx.post(
            f"{self.local_ca_url}/v1/ca/issue-workload",
            json={
                "public_jwk": next_keypair.public_jwk(),
                "pop_jws": pop_jws,
                "ttl_seconds": self.ttl_seconds,
            },
            headers={"Authorization": f"Bearer {sa_jwt}"},
            timeout=5.0,
            trust_env=False,
        )
        resp.raise_for_status()
        ca_data = resp.json()

        own_td = str(ca_data.get("trust_domain") or self.identity.trust_domain)
        own_bundle = ca_data.get("bundle")
        if isinstance(own_bundle, Mapping):
            if self.trust_resolver is not None:
                self.trust_resolver.register_bundle(own_bundle)
            if self.x509_trust_store is not None and (
                own_bundle.get("x509_root_pem") or own_bundle.get("x509_roots_pem")
            ):
                self.x509_trust_store.register_domain_root_pem(
                    own_td, extract_canonical_bundle_root_pem(own_bundle)
                )

        self.identity.update_svid(
            workload_svid=str(ca_data["workload_svid"]),
            issued_at=float(ca_data["issued_at"]),
            expires_at=float(ca_data["expires_at"]),
            keypair=next_keypair,
        )
        if self.mtls_bundle is not None and ca_data.get("x509_leaf_pem"):
            self.mtls_bundle.update_svid(
                leaf_cert_pem=str(ca_data["x509_leaf_pem"]),
                keypair=next_keypair,
            )

        with self._lock:
            self.renewal_count += 1
            self.last_error = None
            cbs = list(self._callbacks)

        for cb in cbs:
            cb(self.identity, self.mtls_bundle)

        return ca_data

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()

        def _loop() -> None:
            retry_backoff = 0.5
            while not self._stop.is_set():
                if self.should_renew():
                    try:
                        self.renew_once()
                        retry_backoff = 0.5
                    except Exception as exc:
                        with self._lock:
                            self.last_error = f"{type(exc).__name__}: {exc}"
                        self._stop.wait(min(self.check_interval_sec, retry_backoff))
                        retry_backoff = min(5.0, retry_backoff * 1.6)
                        continue
                self._stop.wait(self.check_interval_sec)

        self._thread = threading.Thread(
            target=_loop,
            name=f"svid-renewer-{self.identity.parsed_spiffe.default_hop_segment}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


def bootstrap_autonomous_workload(
    local_ca_url: str,
    peer_ca_urls: Optional[Mapping[str, str]] = None,
    sa_token_path: str = K8S_SA_TOKEN_PATH,
    max_wait_sec: float = 45.0,
    require_all_peers: bool = True,
    seed_bundles: Optional[Sequence[Mapping[str, object]]] = None,
    peer_timeout: float = 3.0,
    svid_ttl_seconds: float = 1800.0,
    anchor_store: Optional[TrustAnchorPinStore] = None,
    require_pinned_anchors: bool = False,
    audit_ca_url: Optional[str] = None,
    enable_auto_renewal: bool = True,
    rotate_keypair_on_renewal: bool = False,
    on_renewed: Optional[Callable[[WorkloadIdentity, Optional[WorkloadMTLSBundle]], None]] = None,
    refresh_interval_sec: float = 2.0,
    seed_store: Optional[SeedEndpointStore] = None,
    descriptor_store: Optional[DomainDescriptorStore] = None,
    persisted_descriptors_file: Optional[str] = None,
) -> Tuple[WorkloadIdentity, TrustBundleResolver, WorkloadMTLSBundle, FederationBundleSyncer]:
    """Generate RAM-only ES256 keypair, obtain `JWT-SVID` + `X.509-SVID` from local CA,
    synchronize federated JWKS + X.509 Root CAs + Signed Domain Descriptors across peer domains,
    and start automatic 50%-lifetime background SVID/X.509 renewal.
    """
    resolved_tok_path = resolve_sa_token_path(sa_token_path)
    keypair = KeyPair.generate("ES256")
    eff_ttl = max(4.0, float(svid_ttl_seconds))
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
                    "ttl_seconds": eff_ttl,
                },
                headers={"Authorization": f"Bearer {sa_jwt}"},
                timeout=5.0,
                trust_env=False,
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

    own_td = str(ca_data["trust_domain"])
    own_bundle = ca_data.get("bundle")
    own_anchor: Optional[str] = None
    if isinstance(own_bundle, Mapping):
        own_anchor = compute_bundle_trust_anchor(own_bundle)
    if descriptor_store is not None:
        descriptor_store.set_local_trust_domain(own_td, own_anchor)

    syncer = FederationBundleSyncer(
        peer_ca_urls=peer_ca_urls,
        timeout=peer_timeout,
        anchor_store=anchor_store,
        require_pinned_anchors=require_pinned_anchors,
        audit_ca_url=audit_ca_url,
        local_trust_domain=own_td,
        seed_store=seed_store,
        descriptor_store=descriptor_store,
        local_ca_url=local_ca_url,
        sa_token_path=sa_token_path,
        persisted_descriptors_file=persisted_descriptors_file,
    )
    # Seed own domain bundle immediately, plus any pre-cached public peer bundles/descriptors
    if isinstance(own_bundle, Mapping):
        syncer.trust_resolver.register_bundle(own_bundle)
        if own_bundle.get("x509_root_pem") or own_bundle.get("x509_roots_pem"):
            syncer.x509_trust_store.register_domain_root_pem(
                own_td, extract_canonical_bundle_root_pem(own_bundle)
            )
    raw_ca_descs = ca_data.get("descriptors")
    if descriptor_store is not None and isinstance(raw_ca_descs, list):
        for raw_d in raw_ca_descs:
            if isinstance(raw_d, Mapping):
                try:
                    _, v_desc = descriptor_store.ingest_raw_descriptor(raw_d)
                    syncer.apply_verified_descriptor(v_desc)
                except Exception:
                    continue
    if seed_bundles:
        for sb in seed_bundles:
            if isinstance(sb, Mapping) and sb.get("trust_domain"):
                sb_td = str(sb["trust_domain"])
                if sb.get("keys"):
                    syncer.trust_resolver.register_bundle(sb)
                if sb.get("x509_root_pem") or sb.get("x509_roots_pem"):
                    syncer.x509_trust_store.register_domain_root_pem(
                        sb_td, extract_canonical_bundle_root_pem(sb)
                    )
    if require_all_peers:
        syncer.sync_all(require_all=True, max_wait_sec=max_wait_sec)
    syncer.start_background_refresh(interval_sec=refresh_interval_sec)

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
    if enable_auto_renewal:
        renewer = WorkloadIdentityRenewer(
            local_ca_url=local_ca_url,
            identity=identity,
            mtls_bundle=mtls_bundle,
            trust_resolver=syncer.trust_resolver,
            x509_trust_store=syncer.x509_trust_store,
            sa_token_path=sa_token_path,
            ttl_seconds=eff_ttl,
            rotate_keypair=rotate_keypair_on_renewal,
            on_renewed=on_renewed,
        )
        syncer.identity_renewer = renewer
        renewer.start()

    return identity, syncer.trust_resolver, mtls_bundle, syncer
