# Lineage Capability Tree (LCT): Full-Lifecycle Cryptographic Governance for Cross-Organization Multi-Agent & MCP Networks

`lineage/` implements the **Lineage Capability Tree (LCT)** governance framework across **multi-cluster Kubernetes federations, Official A2A (Agent2Agent) v1.0 streaming workflows, and Model Context Protocol (MCP) tool servers**.

Large binary caches (`.tools/`, `venv/`, `.venv/`) and upstream vendor checkouts (`src/`) are excluded from Git via [`.gitignore`](../.gitignore) and automatically provisioned on any machine via [`scripts/setup_deps.sh`](./scripts/setup_deps.sh).

---

## 1. Quick Start (1-Command Dependency Setup & Verification)

```bash
# 1. Inspect or bootstrap Python + Polyglot SDK dependencies
bash lineage/scripts/setup_deps.sh --check
bash lineage/scripts/setup_deps.sh --lang all

# 2. Run the full unit, adversarial security regression, polyglot SDK & benchmark suite
.venv/bin/python3 -W default -m lineage.tests.run_all
# (or use existing host venv if present: python3 -W default -m lineage.tests.run_all)
```

To also provision local Kubernetes binaries (`kind v0.33.0`, `helm v3.22.1`, `kubectl v1.32.2`) into `.tools/bin/` on a fresh machine:

```bash
bash lineage/scripts/setup_deps.sh --lang all --install-k8s-tools
```

---

## 2. Multi-Language `2/2` Sidecar Integration (`Python` / `Go` / `Node.js` / `Java` / `Rust`)

All cryptographic identity, X.509-SVID mTLS 1.3 (`NameConstraints`), RFC 9449 DPoP sender-binding, offline `PermissionLattice` attenuation, risk-anchored cascading revocation, and signed hash-chain auditing run inside the out-of-process **`lct-sidecar`** container. Business agents and MCP servers in **any language** communicate strictly over Pod-local loopback (`127.0.0.1:9001` <-> `127.0.0.1:8081`) authenticated via constant-time `/var/run/lct-loopback/secret`.

Scaffold a ready-to-deploy agent directory in any supported language:

```bash
bash lineage/scripts/configure_agent_lang.sh \
  --lang go \
  --target ./my-go-agent \
  --name go-flight-specialist \
  --domain org-beta.io \
  --skill travel.flight
```

See [`sdk/MULTILANG_GUIDE.md`](./sdk/MULTILANG_GUIDE.md) for detailed documentation on [`sdk/python`](./sdk/python), [`sdk/go`](./sdk/go), [`sdk/node`](./sdk/node), [`sdk/java`](./sdk/java), and [`sdk/rust`](./sdk/rust).

---

## 3. Live 4-Cluster Physical Kubernetes Federation + Ollama (`qwen2.5:3b`) E2E

Provision **4 physically independent Kind clusters** (`lct-org-alpha`, `lct-org-beta`, `lct-org-pay`, `lct-audit`) with disjoint L3 Pod/Service CIDRs, independent `kube-apiserver` OIDC signing keys, CoreDNS public organization FQDNs, dual-port mTLS 1.3 control-plane boundaries, and whole-cluster network partition `503` fail-closed & autonomous recovery:

```bash
bash lineage/k8s/run-e2e-multicluster-ollama.sh
```

Non-destructive cleanup of the 4 `lct-*` clusters:

```bash
bash lineage/k8s/cleanup-multicluster-k8s.sh
```

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) and [`k8s/K8S_DEPLOYMENT.md`](./k8s/K8S_DEPLOYMENT.md) for full protocol & topology details.

---

## 4. 4-Machine Identity-Addressed Physical Federation (`lineage/multihost/`)

Deploy autonomous LCT roles (`alpha`, `beta`, `pay`, `audit` — `1:1` across **4 physical machines** or any role combination) over a standard RFC1918 LAN (macOS, Linux, or Windows + WSL2) with **Identifier / Locator Separation**: zero static peer IP flags, zero global port conventions, zero CoreDNS cross-cluster `hosts` entries, automatic host LAN IP detection (`locator-agent.py`), SSH-style SHA-256 trust anchor pinning (`trust import`), bidirectional signed descriptor gossip, SPIFFE-pinned TLS 1.3 (`0` IP-literal SNI), and zero-restart DHCP IP switching:

```bash
# 1. Machine 1 (alpha — initial seedless hub node; auto-detects LAN IP & local NodePorts)
bash lineage/scripts/multihost.sh deploy --roles alpha
# -> Prints shareable seed (e.g., --seed 10.29.77.23:30100) and org-alpha.io sha256:...

# 2. Machine 2 (beta), Machine 3 (pay), Machine 4 (audit) — each needs ONLY --seed <Machine1_IP:Port>
bash lineage/scripts/multihost.sh deploy --roles beta --seed <M1_IP:PORT>
bash lineage/scripts/multihost.sh deploy --roles pay --seed <M1_IP:PORT>
bash lineage/scripts/multihost.sh deploy --roles audit --seed <M1_IP:PORT>

# 3. Combine the 4 domain anchor lines into anchors.txt & import on each machine (displays & confirms)
bash lineage/scripts/multihost.sh trust import anchors.txt

# 4. Inspect signed descriptors/cards, run A2A v1.0 E2E, & compare OAuth 2.0 RFC 8693 vs LCT
bash lineage/scripts/multihost.sh locator show
bash lineage/scripts/multihost.sh status
bash lineage/scripts/multihost.sh send --text "Book Tokyo flight and hotel for Alice" --stream
bash lineage/scripts/multihost.sh e2e
bash lineage/scripts/multihost.sh compare
```

By default, `alpha` deploys a real **`quay.io/keycloak/keycloak:26.5.2`** OIDC / RFC 8693 Token Exchange container (`--sts-engine auto|keycloak|lightweight|none`, `--delegation-mode dual`), bridging Hop-0 human OIDC logins (`RS256` `user_oidc_token`) into LCT `RootBlock` `B_0` while allowing side-by-side empirical comparison of **`oauth_centralized`**, **`oauth_federated`**, and **`lct`** on the exact same 4-cluster deployment (`multihost.sh compare`).

See [`multihost/MULTIHOST_GUIDE.md`](./multihost/MULTIHOST_GUIDE.md) for Windows `-Profile Any` firewall setup, WSL2 multi-NIC `--advertise-ip` & daemon lifecycle, live role migration, OAuth 2.0 vs. LCT protocol comparison, fault injection, and troubleshooting.

---

## 5. Platform v2 / v2.1: Symmetric Peer-to-Peer Workspace Assistants, 12-Scenario Vertical Suite & 24-Node Scale Benchmark (Milestones 9–10)

Platform v2.1 (`--topology workspace --registry-mode centralized|federated`) deploys symmetric autonomous peer assistants (`assistant-alice`, `assistant-bob` + standby + `assistant-dave` + `beta-user-gateway`, `assistant-carol` + standby + `assistant-vault`) backed by **1 Untrusted Public Yellow Pages** (`0` private keys, `0` auth state, `0` audit logs), multi-org OIDC principal mapping (`user:alice@org-alpha.io`, `user:bob@org-beta.io`, `user:carol@org-payment.io`), and **0 Central Audit Collectors** (`LocalAuditStore` per node + stateless on-demand `DistributedAuditor` targeted BFS pull):

```bash
# 1. Deploy 3-domain symmetric workspace peers (alpha + beta + pay; zero audit cluster needed!)
bash lineage/scripts/multihost.sh deploy \
  --roles alpha,beta,pay \
  --topology workspace \
  --registry-mode centralized \
  --wait-all-ready

# 2. Run all 11 live E2E phases (covering all 12 catalog scenarios across Financial Risk Control,
#    Enterprise Legal & Procurement, and Healthcare Federated Cohort Aggregation)
bash lineage/scripts/multihost.sh workspace-demo

# 3. Query any task's causal DAG on-demand via stateless DistributedAuditor (0 central collector)
bash lineage/scripts/multihost.sh audit <task_id> --distributed

# 4. Run the 4 / 12 / 24-peer distributed scaling & decentralized audit benchmark
bash lineage/scripts/multihost.sh scale-bench --tiers 4,12,24 --output-dir lineage/scale/results

# 5. Optional Real-World Open-Source Pi Agent (@mariozechner/pi-agent-core + qwen2.5:3b / cloud LLM) Case Studies (Milestone 11)
bash lineage/scripts/multihost.sh deploy \
  --roles alpha,beta,pay \
  --topology workspace \
  --registry-mode centralized \
  --with-pi-agent \
  --wait-all-ready
bash lineage/scripts/multihost.sh pi-demo --output-dir ./pi-case-study-results
```

---

## 6. Safe GitHub Packaging & Push (`push_to_github.sh`)

```bash
# Pre-flight verification (0 files > 50 MB, 0 private keys/tokens, .tools/ & src/ excluded)
bash lineage/scripts/push_to_github.sh --dry-run

# Push to https://github.com/Hulalalalalalalalalalala/sc_Agent_security.git
bash lineage/scripts/push_to_github.sh
```
