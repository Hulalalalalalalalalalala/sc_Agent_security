"""LLM-Driven Intent-to-Skill Planner with Strict Lattice Clamping (`WorkspaceIntentRouter`)."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from lineage.agents.ollama_client import OllamaClient, OllamaError
from lineage.protocol.lattice import PermissionLattice

_PROJECT_CODE_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")

SKILL_DEFAULT_TOOL_MAP: Dict[str, Tuple[List[str], List[str]]] = {
    "workspace.tech_review": (
        ["reserve_cloud_budget", "query_operation_status"],
        ["cloud-infra-escrow"],
    ),
    "workspace.biz_procurement": (
        ["procure_vendor_quote", "query_operation_status"],
        ["vendor-procurement-escrow"],
    ),
    "workspace.deep_analysis": (
        ["record_compliance_note"],
        ["compliance-ledger"],
    ),
}

SKILL_LOGICAL_BRANCH_NAME: Dict[str, str] = {
    "workspace.tech_review": "TechReviewBob",
    "workspace.biz_procurement": "BizProcurementCarol",
    "workspace.deep_analysis": "DeepAnalysisDave",
}


def canonicalize_project_code(raw: Any, default: str = "PRJ-ATLAS") -> str:
    s = str(raw or "").strip().upper()
    if not s:
        return default
    s = re.sub(r"[^A-Z0-9._-]+", "-", s).strip("-")
    if not s or not _PROJECT_CODE_RE.match(s):
        return default
    return s[:64]


@dataclass(frozen=True)
class PlannedPeerBranch:
    """Validated, lattice-clamped peer delegation branch produced by `WorkspaceIntentRouter`."""

    logical_branch_id: str
    required_skill: str
    allocated_budget_usd: float
    project_code: str
    attenuated_permissions: PermissionLattice

    def to_dict(self) -> Dict[str, Any]:
        return {
            "logical_branch_id": self.logical_branch_id,
            "required_skill": self.required_skill,
            "allocated_budget_usd": self.allocated_budget_usd,
            "project_code": self.project_code,
            "attenuated_permissions": self.attenuated_permissions.to_dict(),
        }


@dataclass(frozen=True)
class WorkspaceIntentPlan:
    """Validated multi-peer collaboration plan derived from Yellow Pages + `qwen2.5:3b`."""

    project_code: str
    summary: str
    branches: Tuple[PlannedPeerBranch, ...]
    requires_vault_convergence: bool
    available_peer_skills: Tuple[str, ...]
    llm_trace: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_code": self.project_code,
            "summary": self.summary,
            "branches": [b.to_dict() for b in self.branches],
            "requires_vault_convergence": self.requires_vault_convergence,
            "available_peer_skills": list(self.available_peer_skills),
            "llm_trace": self.llm_trace,
        }


class WorkspaceIntentRouter:
    """Maps natural-language workspace intents onto live Yellow Pages skills via `qwen2.5:3b`.

    Every LLM-proposed budget and tool list is strictly intersected against `parent_permissions`
    (`P_branch = P_parent ⊓ P_proposed`), guaranteeing prompt injection can NEVER escalate
    authority beyond the caller's cryptographic LCT capability!
    """

    def __init__(self, ollama: Optional[OllamaClient] = None) -> None:
        self.ollama = ollama

    def plan_collaboration(
        self,
        user_prompt: str,
        available_peers: Sequence[Mapping[str, Any]],
        parent_permissions: Optional[PermissionLattice] = None,
        default_project_code: str = "PRJ-ATLAS",
        only_skills: Optional[Iterable[str]] = None,
    ) -> WorkspaceIntentPlan:
        discovered_skills: List[str] = sorted(
            {
                str(sk)
                for p in available_peers
                for sk in (p.get("skills") or ())
                if str(sk).startswith("workspace.")
                and str(sk) != "workspace.orchestrate"
            }
        )
        if not discovered_skills:
            discovered_skills = ["workspace.tech_review", "workspace.biz_procurement"]

        allowed_skill_filter = (
            {str(s) for s in only_skills if str(s).strip()}
            if only_skills is not None
            else None
        )

        llm_meta: Optional[Dict[str, Any]] = None
        raw_plan: Dict[str, Any] = {}
        if self.ollama is not None:
            catalog_text = ", ".join(discovered_skills)
            raw_plan, llm_meta = self.ollama.chat_json(
                system_prompt=(
                    "You are Alice's Workspace Assistant Planner. Given available peer skills "
                    f"[{catalog_text}], reply strictly in JSON with keys: "
                    "project_code (string, e.g. 'PRJ-ATLAS'), "
                    "selected_skills (array of skill strings from available peer skills), "
                    "tech_budget_usd (number), "
                    "procurement_budget_usd (number), "
                    "summary (short string)."
                ),
                user_prompt=user_prompt,
            )

        proj_code = canonicalize_project_code(
            raw_plan.get("project_code"), default=default_project_code
        )
        if parent_permissions is not None:
            pw_dict = dict(parent_permissions.param_whitelist)
            if "project_code" in pw_dict:
                allowed_codes = sorted(pw_dict["project_code"])
                if allowed_codes and proj_code not in allowed_codes:
                    proj_code = allowed_codes[0]

        raw_selected = raw_plan.get("selected_skills")
        selected: List[str] = []
        if isinstance(raw_selected, list):
            for s in raw_selected:
                s_str = str(s).strip()
                if s_str in SKILL_DEFAULT_TOOL_MAP and s_str in discovered_skills and s_str not in selected:
                    selected.append(s_str)

        # Ensure prompt intent keywords deterministically retain required collaborative peers
        # if a small 3B model omits one of the explicitly requested skills while keeping LLM trace!
        prompt_l = user_prompt.lower()
        if (
            not selected
            or ("tech" in prompt_l or "cloud" in prompt_l or "bob" in prompt_l)
            and "workspace.tech_review" in discovered_skills
            and "workspace.tech_review" not in selected
        ):
            if "workspace.tech_review" in discovered_skills:
                selected.insert(0, "workspace.tech_review")
        if (
            ("procure" in prompt_l or "vendor" in prompt_l or "carol" in prompt_l or "joint" in prompt_l)
            and "workspace.biz_procurement" in discovered_skills
            and "workspace.biz_procurement" not in selected
        ):
            selected.append("workspace.biz_procurement")
        if not selected:
            selected = [s for s in ("workspace.tech_review", "workspace.biz_procurement") if s in discovered_skills]

        if allowed_skill_filter is not None:
            selected = [s for s in selected if s in allowed_skill_filter]

        def _bounded_budget(val: Any, fallback: float) -> float:
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                return fallback
            f = float(val)
            if not math.isfinite(f) or f <= 0.0:
                return fallback
            return min(f, 50_000.0)

        tech_b = _bounded_budget(raw_plan.get("tech_budget_usd"), 450.0)
        proc_b = _bounded_budget(raw_plan.get("procurement_budget_usd"), 350.0)
        if (
            parent_permissions is not None
            and parent_permissions.max_amount is not None
            and len(selected) >= 2
        ):
            raw_total = sum(
                tech_b if sk == "workspace.tech_review" else proc_b for sk in selected
            )
            parent_cap_f = float(parent_permissions.max_amount)
            if raw_total > parent_cap_f and raw_total > 0.0:
                scale = parent_cap_f / raw_total
                tech_b = max(1.0, round(tech_b * scale, 2))
                proc_b = max(1.0, round(proc_b * scale, 2))

        planned_branches: List[PlannedPeerBranch] = []
        for sk in selected:
            tools_for_sk, targets_for_sk = SKILL_DEFAULT_TOOL_MAP.get(
                sk, (["query_operation_status"], ["cloud-infra-escrow"])
            )
            proposed_amt = tech_b if sk == "workspace.tech_review" else proc_b
            if parent_permissions is not None and parent_permissions.max_amount is not None:
                proposed_amt = min(proposed_amt, float(parent_permissions.max_amount))

            proposed_lattice = PermissionLattice.create(
                tools=tools_for_sk,
                max_amount=proposed_amt,
                allowed_targets=targets_for_sk,
                param_whitelist={"project_code": [proj_code]},
                max_calls=4,
            )
            clamped = (
                parent_permissions.intersect(proposed_lattice)
                if parent_permissions is not None
                else proposed_lattice
            )
            if clamped.is_empty():
                continue
            eff_amt = float(clamped.max_amount) if clamped.max_amount is not None else proposed_amt
            planned_branches.append(
                PlannedPeerBranch(
                    logical_branch_id=SKILL_LOGICAL_BRANCH_NAME.get(sk, sk.replace(".", "_")),
                    required_skill=sk,
                    allocated_budget_usd=eff_amt,
                    project_code=proj_code,
                    attenuated_permissions=clamped,
                )
            )

        summary_str = str(
            raw_plan.get("summary")
            or f"Coordinated {len(planned_branches)} peer workspace branch(es) for {proj_code}"
        )[:240]
        return WorkspaceIntentPlan(
            project_code=proj_code,
            summary=summary_str,
            branches=tuple(planned_branches),
            requires_vault_convergence=(len(planned_branches) >= 1),
            available_peer_skills=tuple(discovered_skills),
            llm_trace=llm_meta,
        )


__all__ = [
    "PlannedPeerBranch",
    "SKILL_DEFAULT_TOOL_MAP",
    "SKILL_LOGICAL_BRANCH_NAME",
    "WorkspaceIntentPlan",
    "WorkspaceIntentRouter",
    "canonicalize_project_code",
]
