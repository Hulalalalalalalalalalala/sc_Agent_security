# Platform v2 Distributed Peer-to-Peer Scale & Decentralized Audit Benchmark

- **Registry Topology**: `1` Untrusted Public Yellow Pages (`AgentCard` JWS + CA SVID verified; `0` private keys, `0` auth state, `0` audit logs)
- **Audit Topology**: **`0` Central Audit Collectors** (`LocalAuditStore` per peer + stateless on-demand `DistributedAuditor` BFS pull)
- **Autonomous Trust Domains**: `org-alpha.io, org-beta.io, org-gamma.io, org-delta.io`

## 1. Multi-Hop Workflow Latency & Online STS RPC Scaling (`N in {4, 12, 24}`)

| Peer Mesh Size (`N`) | Logical Hops | `oauth_centralized` P50 / P95 (`ms`, STS RPCs) | `oauth_federated` P50 / P95 (`ms`, STS RPCs) | `lct` P50 / P95 (`ms`, STS RPCs) |
| :--- | :--- | :--- | :--- | :--- |
| **`4` Peers** | `5` | `93.48 / 97.05 ms` (`5` RPCs) | `112.46 / 119.36 ms` (`5` RPCs) | **`133.79 / 138.18 ms` (`0` RPCs)** |
| **`24` Peers** | `15` | `182.96 / 183.96 ms` (`18` RPCs) | `190.23 / 195.47 ms` (`18` RPCs) | **`206.14 / 206.97 ms` (`0` RPCs)** |

## 2. Cascading Revocation & Decentralized On-Demand `DistributedAuditor` Scaling

| Peer Mesh Size (`N`) | Revocation Convergence | `DistributedAuditor` Nodes Queried (Targeted BFS) | Signed Entries Pulled | BFS Pull + Verify Latency | Causal DAG Accuracy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`4` Peers** | `4/4` in `91.8 ms` | `7/8` (`1` idle peers skipped) | `14` | `42.72 ms` | **`100.0%` (`0` anomalies)** |
| **`24` Peers** | `24/24` in `500.0 ms` | `14/28` (`14` idle peers skipped) | `43` | `101.04 ms` | **`100.0%` (`0` anomalies)** |
