"""Peer-to-Peer Multi-Entity Workspace Assistant Platform (Platform v2).

Replaces rigid C/S travel booking hierarchies with symmetric autonomous peer
assistants (`assistant-alice`, `assistant-bob`, `assistant-carol`, `assistant-dave`,
`assistant-vault`) backed by:
- Untrusted Public Yellow Pages skill discovery (`AgentDirectoryService`);
- Real `Ollama qwen2.5:3b` intent-to-skill planning with strict lattice clamping;
- Owner-protected private resources (`403 CROSS_PRINCIPAL_DENIED`) & Dual-Principal
  `CoAuthorizedToken` (`lctco1.`) consent intersection;
- Short-TTL task expiry (`401 TASK_AUTH_EXPIRED`) -> signed `TaskCheckpoint` ->
  strict remaining-budget `ContinuationToken`;
- Epoch-invariant `branch_idempotency_key` + pre-takeover status lookup preventing
  double-execution on post-commit response drops.
"""

from lineage.workspace_agents.intent_router import (
    PlannedPeerBranch,
    WorkspaceIntentPlan,
    WorkspaceIntentRouter,
)
from lineage.workspace_agents.peer_apps import (
    IdempotencyConflictError,
    IdempotencyLedger,
    IdempotencyRecord,
    WorkspaceAssistantPeerApp,
    WorkspaceSidecarClient,
    WorkspaceVaultMCPApp,
)

__all__ = [
    "IdempotencyConflictError",
    "IdempotencyLedger",
    "IdempotencyRecord",
    "PlannedPeerBranch",
    "WorkspaceAssistantPeerApp",
    "WorkspaceIntentPlan",
    "WorkspaceIntentRouter",
    "WorkspaceSidecarClient",
    "WorkspaceVaultMCPApp",
]
