# Lineage Capability Tree (LCT) — Multi-Language `2/2` Sidecar Integration Guide

LCT decouples **all cryptographic operations** (SPIFFE JWT-SVID & X.509-SVID mTLS 1.3 handshakes, RFC 9449 DPoP proof generation, offline `PermissionLattice` attenuation, risk-anchored revocation checks, atomic prune-and-graft failover, and signed hash-chain audit emission) into the out-of-process **`lct-sidecar`** container.

Your business Agent or MCP Tool container (`app`) can be written in **any programming language (`Python`, `Go`, `Node.js/TypeScript`, `Java`, `Rust`, etc.)** with **zero cryptographic libraries, zero private keys, and zero Kubernetes ServiceAccount tokens** mounted inside `app`.

---

## 1. Universal `2/2` Loopback Wire Contract

| Direction | Endpoint | Security & Headers |
| --- | --- | --- |
| **Shared Boot Secret** | `/var/run/lct-loopback/secret` (`emptyDir: Memory`, read-only in `app`) | 256-bit random URL-safe secret generated per Pod boot by `lct-sidecar` |
| **Inbound (`lct-sidecar -> app`)** | `http://127.0.0.1:9001` (`/a2a/task`, `/a2a`, `/mcp`, `/healthz`) | `app` verifies `X-LCT-Loopback-Auth` in **constant time** (`403` on mismatch) and reads verified `X-LCT-Request-Id`, `X-LCT-Task-Id`, `X-LCT-Sub`, `X-LCT-Lineage-Path`, `X-LCT-Decision` |
| **Outbound (`app -> lct-sidecar`)** | `POST http://127.0.0.1:8081/v1/proxy/call` | `app` passes `X-LCT-Loopback-Auth` + `request_id` with `"action": "call_tool"` or `"action": "delegate_agent"` + attenuated `permissions` JSON |

---

## 2. Ready-to-Use Polyglot SDKs & Dependency Directories

| Language | SDK Directory | Dependency Manifest & Setup | Constant-Time Primitive |
| --- | --- | --- | --- |
| **Python 3.11+** | [lineage/sdk/python/](file:///Users/hulalala/Desktop/A/lineage/sdk/python) | `requirements.txt` (`bash lineage/scripts/setup_deps.sh --lang python`) | `hmac.compare_digest` |
| **Go 1.22+** | [lineage/sdk/go/](file:///Users/hulalala/Desktop/A/lineage/sdk/go) | `go.mod` (pure Go stdlib, zero external modules; `bash lineage/scripts/setup_deps.sh --lang go`) | `crypto/subtle.ConstantTimeCompare` |
| **Node.js 18+ / TS** | [lineage/sdk/node/](file:///Users/hulalala/Desktop/A/lineage/sdk/node) | `package.json` + `lct_sdk.d.ts` (zero npm runtime bloat; `bash lineage/scripts/setup_deps.sh --lang node`) | `crypto.timingSafeEqual` |
| **Java 17+** | [lineage/sdk/java/](file:///Users/hulalala/Desktop/A/lineage/sdk/java) | `pom.xml` (pure JDK `HttpServer` + `HttpClient`; `bash lineage/scripts/setup_deps.sh --lang java`) | `MessageDigest.isEqual` |
| **Rust (2021)** | [lineage/sdk/rust/](file:///Users/hulalala/Desktop/A/lineage/sdk/rust) | `Cargo.toml` (zero external crates; `bash lineage/scripts/setup_deps.sh --lang rust`) | `black_box` XOR accumulator |

---

## 3. One-Command Agent Project Scaffolder (`configure_agent_lang.sh`)

Generate a complete, ready-to-build agent directory (including dependency manifest, SDK adapter, runnable agent entrypoint, `Dockerfile`, and customized `k8s-2of2-pod.yaml`) for any of the 5 languages:

```bash
# Example 1: Scaffold a Go agent in Organization Beta
bash lineage/scripts/configure_agent_lang.sh \
  --lang go \
  --target ./my-go-flight-agent \
  --name go-flight-agent \
  --domain org-beta.io \
  --skill travel.flight.quote

# Example 2: Scaffold a Node.js/TypeScript agent in Organization Alpha
bash lineage/scripts/configure_agent_lang.sh \
  --lang node \
  --target ./my-node-planner \
  --name node-planner \
  --domain org-alpha.io \
  --skill travel.plan
```
