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

## 4. Safe GitHub Packaging & Push (`push_to_github.sh`)

```bash
# Pre-flight verification (0 files > 50 MB, 0 private keys/tokens, .tools/ & src/ excluded)
bash lineage/scripts/push_to_github.sh --dry-run

# Push to https://github.com/Hulalalalalalalalalalala/sc_Agent_security.git
bash lineage/scripts/push_to_github.sh
```
