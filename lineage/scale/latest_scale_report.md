# Platform v2 Distributed Peer-to-Peer Scale & Decentralized Audit Benchmark

- **Registry Topology**: `1` Untrusted Public Yellow Pages (`AgentCard` JWS + CA SVID verified; `0` private keys, `0` auth state, `0` audit logs)
- **Audit Topology**: **`0` Central Audit Collectors** (`LocalAuditStore` per peer + stateless on-demand `DistributedAuditor` BFS pull)
- **Autonomous Trust Domains**: `org-alpha.io, org-beta.io, org-gamma.io, org-delta.io`

## 1. Multi-Hop Workflow Latency & Online STS RPC Scaling (`N in {4, 12, 24}`)

| Peer Mesh Size (`N`) | Logical Hops | `oauth_centralized` P50 / P95 (`ms`, STS RPCs) | `oauth_federated` P50 / P95 (`ms`, STS RPCs) | `lct` P50 / P95 (`ms`, STS RPCs) |
| :--- | :--- | :--- | :--- | :--- |
| **`4` Peers** | `5` | `84.17 / 84.58 ms` (`5` RPCs) | `95.06 / 107.04 ms` (`5` RPCs) | **`97.49 / 101.23 ms` (`0` RPCs)** |
| **`24` Peers** | `15` | `170.35 / 176.13 ms` (`18` RPCs) | `180.53 / 195.02 ms` (`18` RPCs) | **`208.32 / 213.77 ms` (`0` RPCs)** |

## 2. Cascading Revocation & Decentralized On-Demand `DistributedAuditor` Scaling

| Peer Mesh Size (`N`) | Revocation Convergence | `DistributedAuditor` Nodes Queried (Targeted BFS) | Signed Entries Pulled | BFS Pull + Verify Latency | Causal DAG Accuracy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`4` Peers** | `4/4` in `82.19 ms` | `7/8` (`1` idle peers skipped) | `14` | `31.56 ms` | **`100.0%` (`0` anomalies)** |
| **`24` Peers** | `24/24` in `410.86 ms` | `14/28` (`14` idle peers skipped) | `43` | `85.71 ms` | **`100.0%` (`0` anomalies)** |
