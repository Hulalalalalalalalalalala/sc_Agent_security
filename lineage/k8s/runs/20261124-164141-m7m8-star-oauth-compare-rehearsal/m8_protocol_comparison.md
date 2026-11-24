# Empirical Protocol Comparison (`run_id=m8cmp-1795514645`, `alpha_sts=keycloak-26.5.2`)

| Dimension | `oauth_centralized` (RFC 8693 Central STS) | `oauth_federated` (Per-Org STS Relay) | `lct` (Hop-0 OIDC/Keycloak -> Offline LCT) |
| :--- | :--- | :--- | :--- |
| **1. Multi-Hop Latency & STS RPCs** (`Alpha -> Beta -> Pay -> MCP`) | `12` online STS RPCs (`3165.33 ms` STS RTT, `11360.59 ms` wall) | `12` online STS RPCs (`2954.64 ms` STS RTT, `7616.97 ms` wall) | **`0` downstream STS RPCs** (`0.0 ms` STS RTT, `65.68 ms` Hop-0 bridge, `5752.19 ms` wall) |
| **2. Fine-Grained Parameter Over-Privilege** (`$950` / `Paris` vs `$650` / `Tokyo`) | HTTP `200` (`ALLOWED_BY_FLAT_SCOPE` — `$950.0` `Paris`) | HTTP `200` (`ALLOWED_BY_FLAT_SCOPE` — `$950.0` `Paris`) | **HTTP `403` (`BLOCKED_BY_PERMISSION_LATTICE`)** |
| **3. N-to-1 Convergence & Flight-Only Cancel** | Airline HTTP `200`, Hotel HTTP `200` (`LINEAR_ACT_NO_BRANCH_SCOPED_DEGRADATION`) | Airline HTTP `200`, Hotel HTTP `200` (`LINEAR_ACT_NO_BRANCH_SCOPED_DEGRADATION`) | **Airline HTTP `403` (Blocked), Hotel HTTP `200` (`ALLOW_DEGRADED_DAG`)** |
| **4. Slow Primary Zombie Wakeup on Failover** | Zombie MCP HTTP `200` (`double_spend_prevented=False`) | Zombie MCP HTTP `200` (`double_spend_prevented=False`) | **Zombie MCP HTTP `403` (`double_spend_prevented=True`)** |
| **5. Central `alpha-sts` Partition Impact** | HTTP `502` (`survives=False`) | `Beta->Pay` HTTP `200` (`downstream_survives=True`) | **`Alpha->Beta->Pay` HTTP `200` (`survives=True`, `0` STS calls)** |
| **6. Causal Audit DAG Reconstruction** | `0.0%` (`0` task-linked DAG events) | `0.0%` (`0` task-linked DAG events) | **`100.0%` (`30` verified events, `0` tampered)** |
