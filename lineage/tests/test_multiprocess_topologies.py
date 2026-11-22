"""Real OS Multi-Process End-to-End Integration Tests for 1-to-N, N-to-1, and M-to-N Topologies.

Every Control-Plane service (`AgentDirectoryService`, `RevocationService`, `AuditCollectorService`)
and every Data-Plane node (`AgentSidecarNode`, `MCPToolSidecarNode`) runs in its own isolated
OS process (`multiprocessing` `'spawn'` context) communicating strictly over real TCP HTTP sockets.
Each child process generates its own `ES256` private key in-memory and requests only a public-JWK
attested SVID—zero private keys ever cross IPC pipes or touch disk!
"""

from __future__ import annotations

import concurrent.futures
import multiprocessing as mp
import signal
import time
import unittest
from typing import Any, Dict, List, Mapping, Tuple

import httpx

from lineage.audit import (
    AuditCollectorClient,
    AuditCollectorService,
    AuditEventType,
    AuditStreamEmitter,
    CausalChainAuditor,
)
from lineage.common.crypto import KeyPair
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.identity import TrustBundleResolver, TrustDomainCA, WorkloadIdentity
from lineage.protocol import PermissionLattice, create_dpop_proof, mint_root_token
from lineage.registry import AgentDirectoryClient, AgentDirectoryService
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.sidecar import AgentSidecarNode, MCPToolSidecarNode
from lineage.verifier import VerificationMode


# =============================================================================
# Isolated OS Child Process Entrypoints (Top-Level Picklable Functions for 'spawn')
# =============================================================================


def _bootstrap_workload_in_process(
    ca_url: str, trust_domain: str, workload_path: str
) -> Tuple[WorkloadIdentity, TrustBundleResolver]:
    """Generate fresh ES256 private key INSIDE child OS process and fetch public SVID."""
    kp = KeyPair.generate("ES256")
    resp = httpx.post(
        f"{ca_url}/v1/attest",
        json={
            "trust_domain": trust_domain,
            "workload_path": workload_path,
            "public_jwk": kp.public_jwk(),
        },
        timeout=5.0,
    )
    resp.raise_for_status()
    data = resp.json()
    resolver = TrustBundleResolver.from_federation_bundles(data["bundles"])
    identity = WorkloadIdentity(
        spiffe_id=data["spiffe_id"],
        trust_domain=trust_domain,
        keypair=kp,
        workload_svid=data["workload_svid"],
        issued_at=float(data["issued_at"]),
        expires_at=float(data["expires_at"]),
    )
    return identity, resolver


def _run_directory_process(ca_url: str, ready_q: mp.Queue) -> None:
    _, resolver = _bootstrap_workload_in_process(
        ca_url, "org-alpha.io", "/ns/sys/sa/directory"
    )
    svc = AgentDirectoryService(resolver)
    url = svc.start()
    ready_q.put({"url": url})
    signal.signal(signal.SIGTERM, lambda *_: svc.stop())
    svc._http.serve_forever_blocking()


def _run_revocation_process(ca_url: str, ready_q: mp.Queue) -> None:
    identity, resolver = _bootstrap_workload_in_process(
        ca_url, "org-alpha.io", "/ns/sys/sa/revocation"
    )
    svc = RevocationService(identity, resolver)
    url = svc.start()
    ready_q.put({"url": url, "spiffe_id": identity.spiffe_id})
    signal.signal(signal.SIGTERM, lambda *_: svc.stop())
    svc._http.serve_forever_blocking()


def _run_audit_collector_process(ca_url: str, ready_q: mp.Queue) -> None:
    _, resolver = _bootstrap_workload_in_process(
        ca_url, "org-alpha.io", "/ns/sys/sa/audit-collector"
    )
    svc = AuditCollectorService(trust_resolver=resolver)
    url = svc.start()
    ready_q.put({"url": url})
    signal.signal(signal.SIGTERM, lambda *_: svc.stop())
    svc._http.serve_forever_blocking()


def _run_mcp_tool_process(
    ca_url: str,
    trust_domain: str,
    workload_path: str,
    rev_url: str,
    audit_url: str,
    ready_q: mp.Queue,
) -> None:
    identity, resolver = _bootstrap_workload_in_process(
        ca_url, trust_domain, workload_path
    )

    def _get_weather(args: Mapping[str, Any], _: HTTPRequestContext) -> Dict[str, Any]:
        return {"city": args.get("city", "Unknown"), "temp_f": 68.5, "cond": "clear"}

    def _book_flight(args: Mapping[str, Any], _: HTTPRequestContext) -> Dict[str, Any]:
        return {
            "booked_flight": True,
            "city": args.get("city"),
            "amount": args.get("amount"),
        }

    def _book_hotel(args: Mapping[str, Any], _: HTTPRequestContext) -> Dict[str, Any]:
        return {
            "booked_hotel": True,
            "city": args.get("city"),
            "amount": args.get("amount"),
        }

    def _execute_payment(
        args: Mapping[str, Any], _: HTTPRequestContext
    ) -> Dict[str, Any]:
        return {
            "paid": True,
            "target": args.get("target"),
            "amount": args.get("amount"),
        }

    def _write_ledger(args: Mapping[str, Any], _: HTTPRequestContext) -> Dict[str, Any]:
        return {
            "ledger_committed": True,
            "amount": args.get("amount"),
            "note": args.get("note", ""),
        }

    node = MCPToolSidecarNode(
        identity=identity,
        trust_resolver=resolver,
        tools={
            "get_weather": _get_weather,
            "book_flight": _book_flight,
            "book_hotel": _book_hotel,
            "execute_payment": _execute_payment,
            "write_ledger": _write_ledger,
        },
        mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
        revocation_url=rev_url,
        audit_collector_url=audit_url,
    )
    node.start()
    ready_q.put(
        {
            "mcp_url": node.mcp_url,
            "direct_app_url": node.direct_app_url,
            "spiffe_id": identity.spiffe_id,
            "jkt": identity.jkt,
        }
    )
    signal.signal(signal.SIGTERM, lambda *_: node.stop())
    node.app_http.serve_forever_blocking()


def _generic_agent_handler(
    node: AgentSidecarNode, req: HTTPRequestContext, body: Dict[str, Any]
) -> Tuple[int, Dict[str, Any]]:
    """Composable multi-topology business workflow handler driven by structured task instructions.

    NOTE: Business handler NEVER sees raw tokens or private keys—every outbound call goes
    exclusively through `node.sidecar_*` using the request-scoped `X-LCT-Request-Id`!
    """
    req_id = str(req.header("X-LCT-Request-Id", ""))
    op = str(body.get("op", "call_tool"))

    if op == "call_tool":
        st, res = node.sidecar_call_tool(
            request_id=req_id,
            target_mcp_url=str(body["mcp_url"]),
            tool_name=str(body["tool"]),
            arguments=body.get("arguments") or {},
        )
        return st, {
            "agent": node.identity.spiffe_id,
            "task_id": req.header("X-LCT-Task-Id"),
            "sub": req.header("X-LCT-Sub"),
            "tool_result": res,
        }

    if op == "fanout_1_to_n":
        # Execute parallel 1-to-N differentiated attenuations!
        branches: List[Dict[str, Any]] = list(body["branches"])

        def _exec_branch(br: Dict[str, Any]) -> Tuple[str, int, Dict[str, Any]]:
            perms = PermissionLattice.from_dict(br["permissions"])
            st, out = node.sidecar_delegate(
                request_id=req_id,
                permissions=perms,
                payload=br["payload"],
                required_skill=br.get("skill"),
                hop_segment=br.get("hop_segment"),
                use_prune_and_graft=bool(br.get("use_prune_and_graft", False)),
                timeout=float(br.get("timeout", 2.5)),
            )
            return str(br["name"]), st, out

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(branches))) as ex:
            results = list(ex.map(_exec_branch, branches))

        return (
            200,
            {
                "coordinator": node.identity.spiffe_id,
                "task_id": req.header("X-LCT-Task-Id"),
                "branches": {name: {"status": st, "body": out} for name, st, out in results},
            },
        )

    if op == "delegate_to_converge":
        # Attenuate from specialist B_i to N-to-1 convergence node C's `/a2a/converge`
        perms = PermissionLattice.from_dict(body["permissions"])
        st, out = node.sidecar_delegate(
            request_id=req_id,
            permissions=perms,
            payload={"branch_data": body.get("branch_data") or {}},
            required_skill=str(body["converge_skill"]),
            task_path="/a2a/converge",
            hop_segment=body.get("hop_segment"),
        )
        return st, out

    if op == "execute_converged_tool":
        # Convergence holder C invokes MCP tool using assembled MultiParentToken for `(task_id, sub)`
        task_id = str(req.header("X-LCT-Task-Id"))
        sub = str(req.header("X-LCT-Sub"))
        st, out = node.sidecar_call_tool_converged(
            task_id=task_id,
            sub=sub,
            target_mcp_url=str(body["mcp_url"]),
            tool_name=str(body["tool"]),
            arguments=body.get("arguments") or {},
        )
        return st, out

    if op == "delegate_chain":
        # Recursive M-to-N hop routing (for cycle detection, max_depth, and skip-level tests)
        perms = PermissionLattice.from_dict(body["permissions"])
        target_card = None
        if "explicit_target" in body:
            # Used to test explicit cycle attempt back to an already-visited agent
            from lineage.registry import AgentCard

            target_card = AgentCard.from_dict_and_verify(
                body["explicit_target"], node.sidecar.trust_resolver
            )
        st, out = node.sidecar_delegate(
            request_id=req_id,
            permissions=perms,
            payload=body["next_payload"],
            target_card=target_card,
            required_skill=body.get("skill"),
            hop_segment=body.get("hop_segment"),
            use_prune_and_graft=bool(body.get("use_prune_and_graft", False)),
            timeout=float(body.get("timeout", 2.5)),
        )
        return st, out

    if op == "tool_then_upward_return":
        # Leaf C/D calls MCP tool, waits for optional test sync hook, then returns upward!
        st, tool_res = node.sidecar_call_tool(
            request_id=req_id,
            target_mcp_url=str(body["mcp_url"]),
            tool_name=str(body["tool"]),
            arguments=body.get("arguments") or {},
        )
        if st != 200:
            return st, tool_res

        # Notify test harness if requested (e.g. so test kills MidRelay OS process right now!)
        hook_url = body.get("kill_parent_hook_url")
        if hook_url:
            httpx.post(str(hook_url), json={"ready_to_return": True}, timeout=5.0)

        ret_st, ret_out = node.sidecar_return_result(
            request_id=req_id,
            result_payload={
                "leaf_agent": node.identity.spiffe_id,
                "tool_output": tool_res["upstream_body"]["result"]["data"],
            },
            timeout=1.0,
        )
        return ret_st, ret_out

    if op == "inspect_skip_level_inbox":
        tid = str(body["inspect_task_id"])
        return 200, {"skip_level_results": node.sidecar.get_skip_level_results(tid)}

    return 400, {"error": f"unknown_op:{op}"}


def _run_agent_process(
    ca_url: str,
    trust_domain: str,
    workload_path: str,
    name: str,
    skills: List[str],
    priority: int,
    dir_url: str,
    rev_url: str,
    audit_url: str,
    ready_q: mp.Queue,
) -> None:
    identity, resolver = _bootstrap_workload_in_process(
        ca_url, trust_domain, workload_path
    )
    node = AgentSidecarNode(
        identity=identity,
        trust_resolver=resolver,
        name=name,
        skills=skills,
        handler=_generic_agent_handler,
        directory_url=dir_url,
        revocation_url=rev_url,
        audit_collector_url=audit_url,
        priority=priority,
    )
    card = node.start(register_in_directory=True)
    ready_q.put(
        {
            "endpoint": node.endpoint,
            "spiffe_id": identity.spiffe_id,
            "jkt": identity.jkt,
            "public_jwk": identity.public_jwk(),
            "card": card.to_dict(),
        }
    )
    signal.signal(signal.SIGTERM, lambda *_: node.stop())
    node.app_http.serve_forever_blocking()


# =============================================================================
# Multi-Process Topology Test Suite
# =============================================================================


class TestMultiProcessTopologies(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mp_ctx = mp.get_context("spawn")
        cls.procs: List[mp.Process] = []

        # 1. Start 3 independent Trust Domain CAs (`org-alpha.io`, `org-beta.io`, `org-payment.io`)
        cls.ca_alpha = TrustDomainCA("org-alpha.io", alg="ES256")
        cls.ca_beta = TrustDomainCA("org-beta.io", alg="RS256")
        cls.ca_payment = TrustDomainCA("org-payment.io", alg="ES256")
        cls.cas = {
            "org-alpha.io": cls.ca_alpha,
            "org-beta.io": cls.ca_beta,
            "org-payment.io": cls.ca_payment,
        }
        cls.resolver = TrustBundleResolver()
        for ca in cls.cas.values():
            cls.resolver.register_domain_ca(ca)

        def _ca_dispatch(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            if req.method == "POST" and req.path == "/v1/attest":
                b = req.json()
                ca = cls.cas[str(b["trust_domain"])]
                spiffe_id, svid, iat, exp = ca.sign_svid_for_public_jwk(
                    str(b["workload_path"]), b["public_jwk"]
                )
                return (
                    200,
                    {
                        "spiffe_id": spiffe_id,
                        "workload_svid": svid,
                        "issued_at": iat,
                        "expires_at": exp,
                        "bundles": cls.resolver.export_federation_bundles(),
                    },
                    {},
                )
            return 404, {"error": "not_found"}, {}

        cls.ca_http = ManagedHTTPService("federated-ca-attestor", _ca_dispatch)
        cls.ca_url = cls.ca_http.start()

        # 2. Spawn Control-Plane OS Processes
        cls.dir_info = cls._spawn_and_wait(_run_directory_process, (cls.ca_url,))
        cls.rev_info = cls._spawn_and_wait(_run_revocation_process, (cls.ca_url,))
        cls.audit_info = cls._spawn_and_wait(_run_audit_collector_process, (cls.ca_url,))

        cls.dir_url = cls.dir_info["url"]
        cls.rev_url = cls.rev_info["url"]
        cls.audit_url = cls.audit_info["url"]

        cls.dir_client = AgentDirectoryClient(cls.dir_url, cls.resolver)
        cls.rev_client = RevocationReplicaClient(cls.rev_url, cls.resolver)
        cls.audit_client = AuditCollectorClient(cls.audit_url, signer=cls.ca_alpha)
        cls.root_audit_emitter = AuditStreamEmitter(cls.ca_alpha, cls.audit_client)
        cls.driver_identity = cls.ca_alpha.issue_workload("/ns/entry/sa/test-driver")

        # 3. Spawn MCP Tool Server OS Processes (paired with LineageSidecars)
        cls.tool_travel = cls._spawn_and_wait(
            _run_mcp_tool_process,
            (
                cls.ca_url,
                "org-beta.io",
                "/ns/tools/sa/travel-mcp",
                cls.rev_url,
                cls.audit_url,
            ),
        )
        cls.tool_payment = cls._spawn_and_wait(
            _run_mcp_tool_process,
            (
                cls.ca_url,
                "org-payment.io",
                "/ns/tools/sa/payment-mcp",
                cls.rev_url,
                cls.audit_url,
            ),
        )

        # 4. Spawn Business Agent + LineageSidecar OS Processes across 3 Trust Domains
        cls.coord_a = cls._spawn_and_wait(
            _run_agent_process,
            (
                cls.ca_url,
                "org-alpha.io",
                "/ns/coord/sa/coord-a",
                "Coordinator A",
                ["coord.entry"],
                10,
                cls.dir_url,
                cls.rev_url,
                cls.audit_url,
            ),
        )
        cls.worker_weather = cls._spawn_and_wait(
            _run_agent_process,
            (
                cls.ca_url,
                "org-beta.io",
                "/ns/spec/sa/weather-b1",
                "Weather Specialist B1",
                ["weather.ops"],
                10,
                cls.dir_url,
                cls.rev_url,
                cls.audit_url,
            ),
        )
        cls.worker_flight_primary, cls.proc_flight_primary = cls._spawn_and_wait_with_proc(
            _run_agent_process,
            (
                cls.ca_url,
                "org-beta.io",
                "/ns/spec/sa/flight-b2-primary",
                "Flight Specialist Primary",
                ["flight.ops"],
                10,
                cls.dir_url,
                cls.rev_url,
                cls.audit_url,
            ),
        )
        cls.worker_flight_sub = cls._spawn_and_wait(
            _run_agent_process,
            (
                cls.ca_url,
                "org-beta.io",
                "/ns/spec/sa/flight-b2-sub",
                "Flight Specialist Substitute",
                ["flight.ops"],
                20,
                cls.dir_url,
                cls.rev_url,
                cls.audit_url,
            ),
        )
        cls.worker_hotel_pay = cls._spawn_and_wait(
            _run_agent_process,
            (
                cls.ca_url,
                "org-payment.io",
                "/ns/spec/sa/hotel-pay-b3",
                "Hotel & Payment Specialist B3",
                ["hotel.ops", "payment.ops"],
                10,
                cls.dir_url,
                cls.rev_url,
                cls.audit_url,
            ),
        )
        cls.aggregator_c = cls._spawn_and_wait(
            _run_agent_process,
            (
                cls.ca_url,
                "org-payment.io",
                "/ns/dag/sa/aggregator-c",
                "DAG Aggregator C",
                ["dag.converge"],
                10,
                cls.dir_url,
                cls.rev_url,
                cls.audit_url,
            ),
        )
        cls.leaf_d = cls._spawn_and_wait(
            _run_agent_process,
            (
                cls.ca_url,
                "org-alpha.io",
                "/ns/deep/sa/leaf-d",
                "Deep Specialist D",
                ["deep.leaf"],
                10,
                cls.dir_url,
                cls.rev_url,
                cls.audit_url,
            ),
        )

    @classmethod
    def _spawn_and_wait_with_proc(
        cls, target: Any, args: Tuple[Any, ...]
    ) -> Tuple[Dict[str, Any], mp.Process]:
        q: mp.Queue = cls.mp_ctx.Queue()
        proc = cls.mp_ctx.Process(target=target, args=(*args, q), daemon=True)
        proc.start()
        cls.procs.append(proc)
        info = q.get(timeout=15.0)
        return info, proc

    @classmethod
    def _spawn_and_wait(cls, target: Any, args: Tuple[Any, ...]) -> Dict[str, Any]:
        info, _ = cls._spawn_and_wait_with_proc(target, args)
        return info

    @classmethod
    def tearDownClass(cls) -> None:
        for p in reversed(cls.procs):
            if p.is_alive():
                p.terminate()
        for p in reversed(cls.procs):
            p.join(timeout=3.0)
            if p.is_alive():
                p.kill()
        cls.ca_http.stop()

    def _mint_and_log_root(
        self,
        task_id: str,
        sub: str,
        first_hop: Dict[str, Any],
        permissions: PermissionLattice,
        max_depth: int = 6,
    ) -> str:
        tok = mint_root_token(
            authority_ca=self.ca_alpha,
            task_id=task_id,
            sub=sub,
            sender_jkt=self.driver_identity.jkt,
            first_hop_spiffe_id=first_hop["spiffe_id"],
            first_hop_jkt=first_hop["jkt"],
            permissions=permissions,
            max_depth=max_depth,
            hop_segment="CoordA",
            first_hop_public_jwk=first_hop["public_jwk"],
            first_hop_return_endpoint=first_hop["endpoint"],
        )
        self.root_audit_emitter.emit(
            event_type=AuditEventType.ROOT_MINT,
            task_id=task_id,
            sub=sub,
            lineage_path=tok.lineage_path,
            hop_index=0,
            epoch=0,
            root_block_hash=tok.root_block_hash,
            current_block_hash=tok.leaf_block_hash,
            decision="ALLOW",
            permissions_summary=permissions.to_dict(),
        )
        return tok.encode_compact()

    def _post_to_agent(
        self, agent_info: Dict[str, Any], compact_token: str, payload: Dict[str, Any]
    ) -> httpx.Response:
        url = f"{agent_info['endpoint']}/a2a/task"
        dpop = create_dpop_proof(self.driver_identity, "POST", url, compact_token)
        return httpx.post(
            url,
            json=payload,
            headers={"Authorization": f"DPoP {compact_token}", "DPoP": dpop},
            timeout=15.0,
        )

    # -------------------------------------------------------------------------
    # Topology 1: 1-to-N Differentiated Fan-Out + Subtree Cascading Revocation
    # -------------------------------------------------------------------------
    def test_01_one_to_many_fanout_and_subtree_cascading_revocation(self) -> None:
        # Security boundary check: direct connection to MCP tool's internal app port is 403!
        bypass_resp = httpx.post(
            self.tool_travel["direct_app_url"],
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            timeout=3.0,
        )
        self.assertEqual(bypass_resp.status_code, 403)
        self.assertEqual(bypass_resp.json()["error"], "direct_bypass_blocked")

        p_root = PermissionLattice.create(
            tools=["get_weather", "book_flight", "execute_payment"],
            max_amount=1500.0,
            allowed_targets=["airline-corp", "hotel-corp"],
            param_whitelist={"city": ["New York", "London"]},
        )
        compact_t0 = self._mint_and_log_root(
            "mp-1ton-01", "user:alice@org-alpha.io", self.coord_a, p_root
        )

        # Coordinator A fans out 1-to-3 with strictly differentiated sub-lattices:
        # - weather_branch: ONLY get_weather(New York), max_amount=0
        # - flight_branch:  ONLY book_flight(New York), max_amount=800
        # - pay_branch:     ONLY execute_payment(hotel-corp), max_amount=400 (tries 350 -> 200 OK)
        # - overbudget_pay: ONLY execute_payment(hotel-corp), max_amount=400 (tries 450 -> 403 DENIED!)
        fanout_payload = {
            "op": "fanout_1_to_n",
            "branches": [
                {
                    "name": "weather",
                    "skill": "weather.ops",
                    "hop_segment": "B1-weather",
                    "permissions": PermissionLattice.create(
                        tools=["get_weather"],
                        max_amount=0.0,
                        allowed_targets=["airline-corp"],
                        param_whitelist={"city": ["New York"]},
                    ).to_dict(),
                    "payload": {
                        "op": "call_tool",
                        "mcp_url": self.tool_travel["mcp_url"],
                        "tool": "get_weather",
                        "arguments": {"city": "New York"},
                    },
                },
                {
                    "name": "flight",
                    "skill": "flight.ops",
                    "hop_segment": "B2-flight",
                    "permissions": PermissionLattice.create(
                        tools=["book_flight"],
                        max_amount=800.0,
                        allowed_targets=["airline-corp"],
                        param_whitelist={"city": ["New York"]},
                    ).to_dict(),
                    "payload": {
                        "op": "call_tool",
                        "mcp_url": self.tool_travel["mcp_url"],
                        "tool": "book_flight",
                        "arguments": {"city": "New York", "amount": 650.0},
                    },
                },
                {
                    "name": "payment_ok",
                    "skill": "payment.ops",
                    "hop_segment": "B3-pay-ok",
                    "permissions": PermissionLattice.create(
                        tools=["execute_payment"],
                        max_amount=400.0,
                        allowed_targets=["hotel-corp"],
                        param_whitelist={"city": ["New York"]},
                    ).to_dict(),
                    "payload": {
                        "op": "call_tool",
                        "mcp_url": self.tool_payment["mcp_url"],
                        "tool": "execute_payment",
                        "arguments": {"target": "hotel-corp", "amount": 350.0},
                    },
                },
                {
                    "name": "payment_exceeds_attenuated_cap",
                    "skill": "payment.ops",
                    "hop_segment": "B3-pay-over",
                    "permissions": PermissionLattice.create(
                        tools=["execute_payment"],
                        max_amount=400.0,
                        allowed_targets=["hotel-corp"],
                        param_whitelist={"city": ["New York"]},
                    ).to_dict(),
                    "payload": {
                        "op": "call_tool",
                        "mcp_url": self.tool_payment["mcp_url"],
                        "tool": "execute_payment",
                        "arguments": {"target": "hotel-corp", "amount": 450.0},
                    },
                },
            ],
        }
        resp = self._post_to_agent(self.coord_a, compact_t0, fanout_payload)
        self.assertEqual(resp.status_code, 200)
        branches = resp.json()["branches"]
        self.assertEqual(branches["weather"]["status"], 200)
        self.assertEqual(branches["flight"]["status"], 200)
        self.assertEqual(branches["payment_ok"]["status"], 200)
        # 450 > attenuated 400 (even though root allowed 1500!) -> 403 at Payment Tool Sidecar!
        self.assertEqual(
            branches["payment_exceeds_attenuated_cap"]["body"]["upstream_status"], 403
        )

        # Now test Subtree Cascading Revocation: pre-revoke `/mp-1ton-02/CoordA/B2-revoked`
        # BEFORE execution and verify B2's subtree gets 403 while siblings B1 & B3 succeed 100%!
        compact_t2 = self._mint_and_log_root(
            "mp-1ton-02", "user:alice@org-alpha.io", self.coord_a, p_root
        )
        t2_root_entry = self.audit_client.fetch_entries("mp-1ton-02")[0]
        rev_ev = self.rev_client.revoke_prefix(
            self.driver_identity,
            "/mp-1ton-02/CoordA/B2-revoked",
            reason="compromised_branch",
            authority_token=compact_t2,
        )
        self.root_audit_emitter.emit(
            AuditEventType.REVOCATION_ISSUED,
            "mp-1ton-02",
            "user:alice@org-alpha.io",
            "/mp-1ton-02/CoordA/B2-revoked",
            1,
            0,
            t2_root_entry.root_block_hash,
            t2_root_entry.current_block_hash,
            "REVOKED",
            action_detail={"target": rev_ev.target},
        )
        # Note: CoordA also syncs or downstream tool anchors synchronously on HIGH_RISK book_flight!
        resp2 = self._post_to_agent(
            self.coord_a,
            compact_t2,
            {
                "op": "fanout_1_to_n",
                "branches": [
                    {
                        "name": "sibling_weather_alive",
                        "skill": "weather.ops",
                        "hop_segment": "B1-alive",
                        "permissions": PermissionLattice.create(
                            tools=["get_weather"],
                            max_amount=0.0,
                            allowed_targets=["airline-corp"],
                            param_whitelist={"city": ["London"]},
                        ).to_dict(),
                        "payload": {
                            "op": "call_tool",
                            "mcp_url": self.tool_travel["mcp_url"],
                            "tool": "get_weather",
                            "arguments": {"city": "London"},
                        },
                    },
                    {
                        "name": "revoked_flight_branch",
                        "skill": "flight.ops",
                        "hop_segment": "B2-revoked",
                        "permissions": PermissionLattice.create(
                            tools=["book_flight"],
                            max_amount=800.0,
                            allowed_targets=["airline-corp"],
                            param_whitelist={"city": ["London"]},
                        ).to_dict(),
                        "payload": {
                            "op": "call_tool",
                            "mcp_url": self.tool_travel["mcp_url"],
                            "tool": "book_flight",
                            "arguments": {"city": "London", "amount": 500.0},
                        },
                    },
                ],
            },
        )
        b2_res = resp2.json()["branches"]
        self.assertEqual(b2_res["sibling_weather_alive"]["status"], 200)
        # Revoked branch rejected with 403!
        rev_branch_body = b2_res["revoked_flight_branch"]["body"]
        self.assertEqual(rev_branch_body["upstream_status"], 403)

    # -------------------------------------------------------------------------
    # Topology 2: N-to-1 High-Concurrency DAG Isolation + Fagin Multi-Path Revocation
    # -------------------------------------------------------------------------
    def test_02_many_to_one_high_concurrency_isolation_and_fagin_dag_revocation(self) -> None:
        users = ["user:alice", "user:bob", "user:carol", "user:dave"]
        cities = ["New York", "London", "Tokyo", "Paris"]

        def _run_single_diamond_dag(idx: int) -> Tuple[str, str, Dict[str, Any]]:
            tid = f"mp-nto1-{idx:02d}"
            user = users[idx % len(users)]
            city = cities[idx % len(cities)]
            amt_flight = 300.0 + idx * 10.0
            amt_hotel = 200.0 + idx * 5.0

            p_root = PermissionLattice.create(
                tools=["book_flight", "book_hotel", "write_ledger"],
                max_amount=1500.0,
                param_whitelist={"city": [city]},
            )
            tok_compact = self._mint_and_log_root(tid, user, self.coord_a, p_root)

            # Step 1: Fan-out A -> {B2_Flight, B3_Hotel}, each converging into Aggregator C!
            fanout_res = self._post_to_agent(
                self.coord_a,
                tok_compact,
                {
                    "op": "fanout_1_to_n",
                    "branches": [
                        {
                            "name": "b_flight",
                            "skill": "flight.ops",
                            "hop_segment": "B2",
                            "permissions": PermissionLattice.create(
                                tools=["book_flight", "write_ledger"],
                                max_amount=900.0,
                                param_whitelist={"city": [city]},
                            ).to_dict(),
                            "payload": {
                                "op": "delegate_to_converge",
                                "converge_skill": "dag.converge",
                                "hop_segment": "C",
                                "permissions": PermissionLattice.create(
                                    tools=["book_flight", "write_ledger"],
                                    max_amount=900.0,
                                    param_whitelist={"city": [city]},
                                ).to_dict(),
                                "branch_data": {"leg": "flight", "city": city},
                            },
                        },
                        {
                            "name": "b_hotel",
                            "skill": "hotel.ops",
                            "hop_segment": "B3",
                            "permissions": PermissionLattice.create(
                                tools=["book_hotel", "write_ledger"],
                                max_amount=500.0,
                                param_whitelist={"city": [city]},
                            ).to_dict(),
                            "payload": {
                                "op": "delegate_to_converge",
                                "converge_skill": "dag.converge",
                                "hop_segment": "C",
                                "permissions": PermissionLattice.create(
                                    tools=["book_hotel", "write_ledger"],
                                    max_amount=500.0,
                                    param_whitelist={"city": [city]},
                                ).to_dict(),
                                "branch_data": {"leg": "hotel", "city": city},
                            },
                        },
                    ],
                },
            )
            self.assertEqual(fanout_res.status_code, 200)

            # Step 2: Trigger Aggregator C to execute BOTH `book_flight` and `book_hotel`
            # using its assembled MultiParentToken for `(tid, user)`!
            trigger_res = self._post_to_agent(
                self.coord_a,
                tok_compact,
                {
                    "op": "delegate_chain",
                    "skill": "dag.converge",
                    "hop_segment": "C-trig",
                    "permissions": PermissionLattice.create(
                        tools=["write_ledger"],
                        max_amount=10.0,
                        param_whitelist={"city": [city]},
                    ).to_dict(),
                    "next_payload": {
                        "op": "execute_converged_tool",
                        "mcp_url": self.tool_travel["mcp_url"],
                        "tool": "book_flight",
                        "arguments": {"city": city, "amount": amt_flight},
                    },
                },
            )
            self.assertEqual(trigger_res.status_code, 200)
            up_body = trigger_res.json()["upstream_body"]["upstream_body"]["result"]

            # Also verify cross-city isolation: trying another user's city MUST be 403!
            wrong_city = cities[(idx + 1) % len(cities)]
            wrong_res = self._post_to_agent(
                self.coord_a,
                tok_compact,
                {
                    "op": "delegate_chain",
                    "skill": "dag.converge",
                    "hop_segment": "C-wrong",
                    "permissions": PermissionLattice.create(
                        tools=["write_ledger"],
                        max_amount=10.0,
                        param_whitelist={"city": [city]},
                    ).to_dict(),
                    "next_payload": {
                        "op": "execute_converged_tool",
                        "mcp_url": self.tool_travel["mcp_url"],
                        "tool": "book_hotel",
                        "arguments": {"city": wrong_city, "amount": amt_hotel},
                    },
                },
            )
            self.assertEqual(wrong_res.json()["upstream_body"]["upstream_status"], 403)
            return tid, user, up_body

        # Execute 12 concurrent N-to-1 diamond workflows across threads hitting the OS processes!
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            outcomes = list(pool.map(_run_single_diamond_dag, range(12)))

        for idx, (tid, user, res_meta) in enumerate(outcomes):
            expected_city = cities[idx % len(cities)]
            self.assertEqual(res_meta["task_id"], tid)
            self.assertEqual(res_meta["sub"], user)
            self.assertEqual(res_meta["data"]["city"], expected_city)

        # Live Multi-Process Fagin DAG Partial Revocation on a diamond task (`mp-fagin-live`):
        tid_fagin = "mp-fagin-live"
        p_fagin = PermissionLattice.create(
            tools=["book_flight", "book_hotel", "write_ledger"],
            max_amount=1500.0,
            param_whitelist={"city": ["Tokyo"]},
        )
        tok_fagin = self._mint_and_log_root(
            tid_fagin, "user:carol", self.coord_a, p_fagin
        )
        self._post_to_agent(
            self.coord_a,
            tok_fagin,
            {
                "op": "fanout_1_to_n",
                "branches": [
                    {
                        "name": "b_flight",
                        "skill": "flight.ops",
                        "hop_segment": "B2",
                        "permissions": PermissionLattice.create(
                            tools=["book_flight", "write_ledger"],
                            max_amount=900.0,
                            param_whitelist={"city": ["Tokyo"]},
                        ).to_dict(),
                        "payload": {
                            "op": "delegate_to_converge",
                            "converge_skill": "dag.converge",
                            "hop_segment": "C",
                            "permissions": PermissionLattice.create(
                                tools=["book_flight", "write_ledger"],
                                max_amount=900.0,
                                param_whitelist={"city": ["Tokyo"]},
                            ).to_dict(),
                        },
                    },
                    {
                        "name": "b_hotel",
                        "skill": "hotel.ops",
                        "hop_segment": "B3",
                        "permissions": PermissionLattice.create(
                            tools=["book_hotel", "write_ledger"],
                            max_amount=500.0,
                            param_whitelist={"city": ["Tokyo"]},
                        ).to_dict(),
                        "payload": {
                            "op": "delegate_to_converge",
                            "converge_skill": "dag.converge",
                            "hop_segment": "C",
                            "permissions": PermissionLattice.create(
                                tools=["book_hotel", "write_ledger"],
                                max_amount=500.0,
                                param_whitelist={"city": ["Tokyo"]},
                            ).to_dict(),
                        },
                    },
                ],
            },
        )
        # Revoke B2 (flight) branch!
        ev_f = self.rev_client.revoke_prefix(
            self.driver_identity,
            f"/{tid_fagin}/CoordA/B2",
            reason="revoke_b2",
            authority_token=tok_fagin,
        )
        # Log revocation with proper task root hash from audit collector so auditor sees full consistency
        fagin_root_entry = self.audit_client.fetch_entries(tid_fagin)[0]
        self.root_audit_emitter.emit(
            AuditEventType.REVOCATION_ISSUED,
            tid_fagin,
            "user:carol",
            f"/{tid_fagin}/CoordA/B2",
            1,
            0,
            fagin_root_entry.root_block_hash,
            fagin_root_entry.current_block_hash,
            "REVOKED",
            action_detail={"target": ev_f.target},
        )

        # 1) `book_hotel` (via surviving B3) -> 200 ALLOW_DEGRADED_DAG!
        degraded_ok = self._post_to_agent(
            self.coord_a,
            tok_fagin,
            {
                "op": "delegate_chain",
                "skill": "dag.converge",
                "hop_segment": "C-eval-hotel",
                "permissions": PermissionLattice.create(
                    tools=["write_ledger"], max_amount=10.0, param_whitelist={"city": ["Tokyo"]}
                ).to_dict(),
                "next_payload": {
                    "op": "execute_converged_tool",
                    "mcp_url": self.tool_travel["mcp_url"],
                    "tool": "book_hotel",
                    "arguments": {"city": "Tokyo", "amount": 350.0},
                },
            },
        )
        hotel_mcp_res = degraded_ok.json()["upstream_body"]["upstream_body"]["result"]
        self.assertEqual(hotel_mcp_res["decision"], "ALLOW_DEGRADED_DAG")

        # 2) `book_flight` (depended on revoked B2) -> 403!
        degraded_deny = self._post_to_agent(
            self.coord_a,
            tok_fagin,
            {
                "op": "delegate_chain",
                "skill": "dag.converge",
                "hop_segment": "C-eval-flight",
                "permissions": PermissionLattice.create(
                    tools=["write_ledger"], max_amount=10.0, param_whitelist={"city": ["Tokyo"]}
                ).to_dict(),
                "next_payload": {
                    "op": "execute_converged_tool",
                    "mcp_url": self.tool_travel["mcp_url"],
                    "tool": "book_flight",
                    "arguments": {"city": "Tokyo", "amount": 350.0},
                },
            },
        )
        flight_err = degraded_deny.json()["upstream_body"]
        self.assertEqual(flight_err["upstream_status"], 403)
        self.assertEqual(
            flight_err["upstream_body"]["error"],
            "REVOKED_DEPENDENCY_INSUFFICIENT_SURVIVING_PATHS",
        )

    # -------------------------------------------------------------------------
    # Topology 3: M-to-N Dynamic Mesh + Cycle/Depth + Live OS Process Kill Recovery
    # -------------------------------------------------------------------------
    def test_03_many_to_many_mesh_and_live_os_process_kill_resilience(self) -> None:
        p_mesh = PermissionLattice.create(
            tools=["book_flight", "write_ledger"], max_amount=1000.0
        )

        # 1. M-to-N Cycle Detection over real OS processes: CoordA -> FlightPrimary -> CoordA (403!)
        tok_cycle = self._mint_and_log_root(
            "mp-m2n-cycle", "user:alice", self.coord_a, p_mesh, max_depth=4
        )
        cycle_resp = self._post_to_agent(
            self.coord_a,
            tok_cycle,
            {
                "op": "delegate_chain",
                "skill": "flight.ops",
                "hop_segment": "Hop1",
                "permissions": p_mesh.to_dict(),
                "next_payload": {
                    "op": "delegate_chain",
                    "explicit_target": self.coord_a["card"],
                    "hop_segment": "LoopBackToA",
                    "permissions": p_mesh.to_dict(),
                    "next_payload": {"op": "call_tool"},
                },
            },
        )
        self.assertEqual(cycle_resp.json()["upstream_status"], 403)
        self.assertIn(
            "cycle", cycle_resp.json()["upstream_body"]["detail"].lower()
        )

        # 2. M-to-N Max-Depth Enforcement (`max_depth=1`: CoordA -> FlightPrimary -> LeafD blocked!)
        tok_depth = self._mint_and_log_root(
            "mp-m2n-depth", "user:alice", self.coord_a, p_mesh, max_depth=1
        )
        depth_resp = self._post_to_agent(
            self.coord_a,
            tok_depth,
            {
                "op": "delegate_chain",
                "skill": "flight.ops",
                "hop_segment": "Hop1",
                "permissions": p_mesh.to_dict(),
                "next_payload": {
                    "op": "delegate_chain",
                    "skill": "deep.leaf",
                    "hop_segment": "Hop2Exceeds",
                    "permissions": p_mesh.to_dict(),
                    "next_payload": {"op": "call_tool"},
                },
            },
        )
        self.assertEqual(depth_resp.json()["upstream_status"], 403)
        self.assertIn("max_depth", depth_resp.json()["upstream_body"]["detail"])

        # 3. LIVE OS PROCESS KILL #1: Kill `proc_flight_primary` with SIGTERM ->
        # Coordinator A automatically executes `Atomic Prune-and-Graft` to `worker_flight_sub`!
        self.proc_flight_primary.terminate()
        self.proc_flight_primary.join(timeout=5.0)
        self.assertFalse(self.proc_flight_primary.is_alive())

        tok_graft = self._mint_and_log_root(
            "mp-m2n-graft", "user:alice", self.coord_a, p_mesh, max_depth=4
        )
        graft_resp = self._post_to_agent(
            self.coord_a,
            tok_graft,
            {
                "op": "delegate_chain",
                "skill": "flight.ops",
                "use_prune_and_graft": True,
                "permissions": PermissionLattice.create(
                    tools=["book_flight"], max_amount=600.0
                ).to_dict(),
                "next_payload": {
                    "op": "call_tool",
                    "mcp_url": self.tool_travel["mcp_url"],
                    "tool": "book_flight",
                    "arguments": {"city": "Boston", "amount": 420.0},
                },
            },
        )
        self.assertEqual(graft_resp.status_code, 200)
        graft_data = graft_resp.json()
        self.assertEqual(graft_data["epoch"], 1)
        self.assertEqual(len(graft_data["failover_receipts"]), 1)
        self.assertEqual(
            graft_data["upstream_body"]["agent"],
            self.worker_flight_sub["spiffe_id"],
        )

        # 4. LIVE OS PROCESS KILL #2: Spawn intermediate relay process `MidRelay`, run
        # `CoordA -> MidRelay -> LeafD`, kill `MidRelay` OS process right after `LeafD` calls tool,
        # and verify `LeafD` delivers via `Authenticated Skip-Level Return` directly to `CoordA`!
        mid_info, proc_mid = self._spawn_and_wait_with_proc(
            _run_agent_process,
            (
                self.ca_url,
                "org-beta.io",
                "/ns/mid/sa/ephemeral-relay",
                "Ephemeral Mid Relay",
                ["ephemeral.relay"],
                10,
                self.dir_url,
                self.rev_url,
                self.audit_url,
            ),
        )

        def _kill_mid_hook(_: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            proc_mid.kill()
            proc_mid.join(timeout=5.0)
            return 200, {"killed": True}, {}

        hook_srv = ManagedHTTPService("kill-mid-hook", _kill_mid_hook)
        hook_url = hook_srv.start()
        try:
            tok_skip = self._mint_and_log_root(
                "mp-m2n-skip", "user:alice", self.coord_a, p_mesh, max_depth=4
            )
            # Note: MidRelay will be terminated mid-request, so CoordA->MidRelay HTTP socket drops,
            # while LeafD delivers its signed SkipLevelReceipt directly to CoordA!
            self._post_to_agent(
                self.coord_a,
                tok_skip,
                {
                    "op": "delegate_chain",
                    "skill": "ephemeral.relay",
                    "hop_segment": "MidRelay",
                    "permissions": PermissionLattice.create(
                        tools=["write_ledger"], max_amount=300.0
                    ).to_dict(),
                    "next_payload": {
                        "op": "delegate_chain",
                        "skill": "deep.leaf",
                        "hop_segment": "LeafD",
                        "permissions": PermissionLattice.create(
                            tools=["write_ledger"], max_amount=200.0
                        ).to_dict(),
                        "next_payload": {
                            "op": "tool_then_upward_return",
                            "mcp_url": self.tool_payment["mcp_url"],
                            "tool": "write_ledger",
                            "arguments": {"amount": 150.0, "note": "skip-test"},
                            "kill_parent_hook_url": hook_url,
                        },
                    },
                },
            )
        finally:
            hook_srv.stop()

        # Query CoordA's skip-level inbox (wait briefly for LeafD's async HTTP return after MidRelay SIGKILL)
        tok_inspect = self._mint_and_log_root(
            "mp-m2n-inspect", "user:alice", self.coord_a, p_mesh
        )
        skip_items: List[Dict[str, Any]] = []
        for _ in range(30):
            insp_resp = self._post_to_agent(
                self.coord_a,
                tok_inspect,
                {"op": "inspect_skip_level_inbox", "inspect_task_id": "mp-m2n-skip"},
            )
            self.assertEqual(insp_resp.status_code, 200)
            skip_items = insp_resp.json()["skip_level_results"]
            if skip_items:
                break
            time.sleep(0.05)
        self.assertEqual(len(skip_items), 1)
        self.assertEqual(
            skip_items[0]["skipped_ancestors"], [mid_info["spiffe_id"]]
        )
        self.assertEqual(
            skip_items[0]["result_payload"]["tool_output"]["ledger_committed"], True
        )

        # 5. Global Causal Audit across ALL tasks & streams in AuditCollectorService (ZERO filtering!)
        all_entries = self.audit_client.fetch_entries()
        auditor = CausalChainAuditor(self.resolver)
        report = auditor.audit(all_entries, check_stream_continuity=True)
        self.assertTrue(report.clean, f"Unexpected anomalies: {report.anomalies}")
        num, den = report.reconstruction_rate
        self.assertEqual(num, den)
        self.assertGreaterEqual(num, 18)
        self.assertIn(
            "VERIFIED_FAILOVER_GRAFT",
            report.tasks["mp-m2n-graft"].resilience_classifications,
        )
        self.assertIn(
            "VERIFIED_SKIP_LEVEL_MERGE",
            report.tasks["mp-m2n-skip"].resilience_classifications,
        )


if __name__ == "__main__":
    unittest.main()
