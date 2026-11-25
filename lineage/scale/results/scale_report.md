# Platform v2 Distributed Peer-to-Peer Scale & Decentralized Audit Benchmark

- **Registry Topology**: `1` Untrusted Public Yellow Pages (`AgentCard` JWS + CA SVID verified; `0` private keys, `0` auth state, `0` audit logs)
- **Audit Topology**: **`0` Central Audit Collectors** (`LocalAuditStore` per peer + stateless on-demand `DistributedAuditor` BFS pull)
- **Autonomous Trust Domains**: `org-alpha.io, org-beta.io, org-gamma.io, org-delta.io`

## 1. Multi-Hop Workflow Latency & Online STS RPC Scaling (`N in {4, 12, 24}`)

| Peer Mesh Size (`N`) | Logical Hops | `oauth_centralized` P50 / P95 (`ms`, STS RPCs) | `oauth_federated` P50 / P95 (`ms`, STS RPCs) | `lct` P50 / P95 (`ms`, STS RPCs) |
| :--- | :--- | :--- | :--- | :--- |
| **`4` Peers** | `5` | `113.89 / 116.46 ms` (`5` RPCs) | `112.8 / 143.18 ms` (`5` RPCs) | **`147.16 / 192.1 ms` (`0` RPCs)** |
| **`12` Peers** | `12` | `207.4 / 218.17 ms` (`14` RPCs) | `212.4 / 244.23 ms` (`14` RPCs) | **`265.29 / 309.97 ms` (`0` RPCs)** |
| **`24` Peers** | `15` | `266.56 / 275.85 ms` (`18` RPCs) | `243.39 / 283.52 ms` (`18` RPCs) | **`333.65 / 364.72 ms` (`0` RPCs)** |

## 2. Cascading Revocation & Decentralized On-Demand `DistributedAuditor` Scaling

| Peer Mesh Size (`N`) | Revocation Convergence | `DistributedAuditor` Nodes Queried (Targeted BFS) | Signed Entries Pulled | BFS Pull + Verify Latency | Causal DAG Accuracy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`4` Peers** | `4/4` in `116.71 ms` | `7/8` (`1` idle peers skipped) | `14` | `37.89 ms` | **`100.0%` (`0` anomalies)** |
| **`12` Peers** | `12/12` in `294.94 ms` | `12/16` (`4` idle peers skipped) | `34` | `86.85 ms` | **`100.0%` (`0` anomalies)** |
| **`24` Peers** | `24/24` in `655.43 ms` | `14/28` (`14` idle peers skipped) | `43` | `110.38 ms` | **`100.0%` (`0` anomalies)** |
