"""Structured Permission Lattice (P, <=, meet) and Disjunctive Multi-Parent Envelope.

Supports:
- Tool allowlist (`tools`, with `"*"` top element)
- MCP/API operation method allowlist (`methods`, with `"*"` top element)
- Numeric upper bounds (`max_amount` and arbitrary `numeric_bounds`)
- Discrete value allowlists (`allowed_scopes`, `allowed_targets`, `param_whitelist`)
- Invocation quota (`max_calls`)
- Strict mathematical partial order `child.is_subset_of(parent)` (P_{i+1} <= P_i)
- Greatest lower bound `child = parent.intersect(mask)` (meet operation)
- Exact Fagin/DAG disjunctive multi-parent evaluation (`CompositePermission`)
  avoiding Cartesian cross-branch privilege amplification.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple


class LatticeError(Exception):
    """Raised on malformed PermissionLattice parameters."""


_SPEND_TOOLS: FrozenSet[str] = frozenset(
    {
        "reserve_cloud_budget",
        "procure_vendor_quote",
        "lock_joint_project",
        "book_flight",
        "book_hotel",
        "reserve_hotel",
        "execute_settlement",
    }
)

_IMPLICIT_TOOL_TARGETS: Dict[str, str] = {
    "reserve_cloud_budget": "cloud-infra-escrow",
    "procure_vendor_quote": "vendor-procurement-escrow",
    "record_compliance_note": "compliance-ledger",
}

_EXPLICIT_TARGET_TOOLS: FrozenSet[str] = frozenset(
    {"execute_settlement", "lock_joint_project"}
)

_TOOL_CONSTRAINABLE_PARAMS: Dict[str, FrozenSet[str]] = {
    "reserve_cloud_budget": frozenset({"project_code"}),
    "procure_vendor_quote": frozenset({"project_code"}),
    "record_compliance_note": frozenset({"project_code"}),
    "lock_joint_project": frozenset({"project_code"}),
    "commit_negotiated_contract": frozenset(
        {"contract_id", "warranty_tier", "unit_price_usd", "max_penalty_pct"}
    ),
    "commit_joint_change": frozenset({"change_id"}),
    "sign_release": frozenset({"release_id"}),
    "cohort_aggregate_stats": frozenset({"study_id"}),
    "federated_cohort_aggregate": frozenset({"study_id"}),
    "legal_redline_review": frozenset({"contract_id"}),
    "book_flight": frozenset({"city"}),
    "book_hotel": frozenset({"city"}),
    "reserve_hotel": frozenset({"city"}),
    "execute_settlement": frozenset({"city"}),
    "record_itinerary_audit": frozenset({"city"}),
}


def _is_valid_number(val: Any) -> bool:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return False
    return math.isfinite(float(val))


def _subset_with_wildcard(child: FrozenSet[str], parent: FrozenSet[str]) -> bool:
    if "*" in parent:
        return True
    if "*" in child:
        return False
    return child.issubset(parent)


def _intersect_with_wildcard(a: FrozenSet[str], b: FrozenSet[str]) -> FrozenSet[str]:
    if "*" in a:
        return b
    if "*" in b:
        return a
    return a.intersection(b)


@dataclass(frozen=True)
class PermissionLattice:
    """Immutable capability lattice element attached to each LCT delegation block."""

    tools: FrozenSet[str] = field(default_factory=frozenset)
    methods: FrozenSet[str] = field(
        default_factory=lambda: frozenset({"initialize", "tools/list", "tools/call"})
    )
    max_amount: Optional[float] = None
    numeric_bounds: Tuple[Tuple[str, float], ...] = ()
    allowed_scopes: Optional[FrozenSet[str]] = None
    allowed_targets: Optional[FrozenSet[str]] = None
    param_whitelist: Tuple[Tuple[str, FrozenSet[str]], ...] = ()
    max_calls: int = 100

    def __post_init__(self) -> None:
        if not isinstance(self.tools, frozenset):
            object.__setattr__(self, "tools", frozenset(str(x) for x in self.tools))
        if not isinstance(self.methods, frozenset):
            object.__setattr__(self, "methods", frozenset(str(x) for x in self.methods))

        if self.max_amount is not None:
            if not _is_valid_number(self.max_amount) or float(self.max_amount) < 0.0:
                raise LatticeError(f"max_amount must be finite and >= 0, got {self.max_amount!r}")
            object.__setattr__(self, "max_amount", float(self.max_amount))

        if isinstance(self.numeric_bounds, Mapping):
            nb_items = sorted((str(k), float(v)) for k, v in self.numeric_bounds.items())
        else:
            nb_items = sorted((str(k), float(v)) for k, v in self.numeric_bounds)
        for k, v in nb_items:
            if not k or not _is_valid_number(v) or v < 0.0:
                raise LatticeError(f"Invalid numeric_bound {k!r}={v!r}")
        object.__setattr__(self, "numeric_bounds", tuple(nb_items))

        if self.allowed_scopes is not None and not isinstance(self.allowed_scopes, frozenset):
            object.__setattr__(
                self, "allowed_scopes", frozenset(str(s) for s in self.allowed_scopes)
            )
        if self.allowed_targets is not None and not isinstance(self.allowed_targets, frozenset):
            object.__setattr__(
                self, "allowed_targets", frozenset(str(t) for t in self.allowed_targets)
            )

        if isinstance(self.param_whitelist, Mapping):
            pw_items = sorted(
                (str(k), frozenset(str(x) for x in vals))
                for k, vals in self.param_whitelist.items()
            )
        else:
            pw_items = sorted(
                (str(k), frozenset(str(x) for x in vals))
                for k, vals in self.param_whitelist
            )
        object.__setattr__(self, "param_whitelist", tuple(pw_items))

        if isinstance(self.max_calls, bool) or not isinstance(self.max_calls, int) or self.max_calls < 0:
            raise LatticeError(f"max_calls must be a non-negative integer, got {self.max_calls!r}")

    @classmethod
    def create(
        cls,
        tools: Iterable[str],
        methods: Iterable[str] = ("initialize", "tools/list", "tools/call"),
        max_amount: Optional[float] = None,
        numeric_bounds: Optional[Mapping[str, float]] = None,
        allowed_scopes: Optional[Iterable[str]] = None,
        allowed_targets: Optional[Iterable[str]] = None,
        param_whitelist: Optional[Mapping[str, Iterable[str]]] = None,
        max_calls: int = 100,
    ) -> "PermissionLattice":
        return cls(
            tools=frozenset(tools),
            methods=frozenset(methods),
            max_amount=max_amount,
            numeric_bounds=tuple(sorted((k, float(v)) for k, v in (numeric_bounds or {}).items())),
            allowed_scopes=frozenset(allowed_scopes) if allowed_scopes is not None else None,
            allowed_targets=frozenset(allowed_targets) if allowed_targets is not None else None,
            param_whitelist=tuple(
                sorted(
                    (k, frozenset(str(x) for x in v))
                    for k, v in (param_whitelist or {}).items()
                )
            ),
            max_calls=max_calls,
        )

    @property
    def numeric_bounds_dict(self) -> Dict[str, float]:
        return dict(self.numeric_bounds)

    @property
    def param_whitelist_dict(self) -> Dict[str, FrozenSet[str]]:
        return dict(self.param_whitelist)

    def is_empty(self) -> bool:
        """Return True if this lattice element represents bottom (permits zero calls)."""
        if not self.tools or not self.methods or self.max_calls <= 0:
            return True
        if self.allowed_scopes is not None and len(self.allowed_scopes) == 0:
            return True
        if self.allowed_targets is not None and len(self.allowed_targets) == 0:
            return True
        for _, vals in self.param_whitelist:
            if len(vals) == 0:
                return True
        return False

    def explain_violation_against(self, parent: "PermissionLattice") -> Optional[str]:
        """Return None if `self <= parent`, else a precise human/audit explanation."""
        if not _subset_with_wildcard(self.tools, parent.tools):
            return f"tools {sorted(self.tools)} is not a subset of parent {sorted(parent.tools)}"
        if not _subset_with_wildcard(self.methods, parent.methods):
            return f"methods {sorted(self.methods)} is not a subset of parent {sorted(parent.methods)}"

        if parent.max_amount is not None:
            if self.max_amount is None:
                return f"child dropped parent max_amount={parent.max_amount}"
            if self.max_amount > parent.max_amount:
                return f"child max_amount={self.max_amount} exceeds parent {parent.max_amount}"

        child_nb = self.numeric_bounds_dict
        for k, parent_bound in parent.numeric_bounds:
            if k not in child_nb:
                return f"child dropped parent numeric_bound {k!r}={parent_bound}"
            if child_nb[k] > parent_bound:
                return f"child numeric_bound {k!r}={child_nb[k]} exceeds parent {parent_bound}"

        if parent.allowed_scopes is not None:
            if self.allowed_scopes is None:
                return "child dropped parent allowed_scopes constraint"
            if not self.allowed_scopes.issubset(parent.allowed_scopes):
                return (
                    f"child allowed_scopes {sorted(self.allowed_scopes)} "
                    f"not subset of {sorted(parent.allowed_scopes)}"
                )

        if parent.allowed_targets is not None:
            if self.allowed_targets is None:
                return "child dropped parent allowed_targets constraint"
            if not self.allowed_targets.issubset(parent.allowed_targets):
                return (
                    f"child allowed_targets {sorted(self.allowed_targets)} "
                    f"not subset of {sorted(parent.allowed_targets)}"
                )

        child_pw = self.param_whitelist_dict
        for k, parent_vals in parent.param_whitelist:
            if k not in child_pw:
                return f"child dropped parent param_whitelist constraint {k!r}"
            if not child_pw[k].issubset(parent_vals):
                return (
                    f"child param_whitelist[{k!r}]={sorted(child_pw[k])} "
                    f"not subset of {sorted(parent_vals)}"
                )

        if self.max_calls > parent.max_calls:
            return f"child max_calls={self.max_calls} exceeds parent {parent.max_calls}"

        return None

    def is_subset_of(self, parent: "PermissionLattice") -> bool:
        """Strict mathematical partial order check: returns True iff `self <= parent`."""
        return self.explain_violation_against(parent) is None

    def intersect(self, other: "PermissionLattice") -> "PermissionLattice":
        """Lattice meet (`self ⊓ other`): greatest lower bound guaranteed <= both."""
        tools = _intersect_with_wildcard(self.tools, other.tools)
        methods = _intersect_with_wildcard(self.methods, other.methods)

        if self.max_amount is None:
            max_amt = other.max_amount
        elif other.max_amount is None:
            max_amt = self.max_amount
        else:
            max_amt = min(self.max_amount, other.max_amount)

        nb_a = self.numeric_bounds_dict
        nb_b = other.numeric_bounds_dict
        merged_nb: Dict[str, float] = {}
        for k in set(nb_a.keys()) | set(nb_b.keys()):
            if k in nb_a and k in nb_b:
                merged_nb[k] = min(nb_a[k], nb_b[k])
            elif k in nb_a:
                merged_nb[k] = nb_a[k]
            else:
                merged_nb[k] = nb_b[k]

        if self.allowed_scopes is None:
            scopes = other.allowed_scopes
        elif other.allowed_scopes is None:
            scopes = self.allowed_scopes
        else:
            scopes = self.allowed_scopes.intersection(other.allowed_scopes)

        if self.allowed_targets is None:
            targets = other.allowed_targets
        elif other.allowed_targets is None:
            targets = self.allowed_targets
        else:
            targets = self.allowed_targets.intersection(other.allowed_targets)

        pw_a = self.param_whitelist_dict
        pw_b = other.param_whitelist_dict
        merged_pw: Dict[str, FrozenSet[str]] = {}
        for k in set(pw_a.keys()) | set(pw_b.keys()):
            if k in pw_a and k in pw_b:
                merged_pw[k] = pw_a[k].intersection(pw_b[k])
            elif k in pw_a:
                merged_pw[k] = pw_a[k]
            else:
                merged_pw[k] = pw_b[k]

        return PermissionLattice(
            tools=tools,
            methods=methods,
            max_amount=max_amt,
            numeric_bounds=tuple(sorted(merged_nb.items())),
            allowed_scopes=scopes,
            allowed_targets=targets,
            param_whitelist=tuple(sorted(merged_pw.items())),
            max_calls=min(self.max_calls, other.max_calls),
        )

    def check_invocation(
        self,
        method: str,
        tool: Optional[str] = None,
        arguments: Optional[Mapping[str, Any]] = None,
        call_index: int = 1,
    ) -> Tuple[bool, str]:
        """Evaluate whether a concrete MCP/tool request satisfies this lattice."""
        if call_index < 1 or call_index > self.max_calls:
            return False, f"call_index {call_index} exceeds max_calls={self.max_calls}"

        if not self.tools or not self.methods:
            return False, "empty capability lattice (bottom)"

        if "*" not in self.methods and method not in self.methods:
            return False, f"method {method!r} not in allowed methods {sorted(self.methods)}"

        if method == "tools/call" or tool is not None:
            if not tool:
                return False, "tools/call requires explicit tool name"
            if "*" not in self.tools and tool not in self.tools:
                return False, f"tool {tool!r} not in allowed tools {sorted(self.tools)}"

        args = arguments or {}
        if not isinstance(args, Mapping):
            return False, "tool arguments must be a mapping"

        tool_schema_params = _TOOL_CONSTRAINABLE_PARAMS.get(tool or "", frozenset())

        # 1. Check max_amount constraint (and require explicit spend arg for known spend tools)
        if self.max_amount is not None:
            found_spend_arg = False
            for amt_key in ("amount", "price", "total", "max_amount"):
                if amt_key in args:
                    found_spend_arg = True
                    val = args[amt_key]
                    if not _is_valid_number(val):
                        return False, f"parameter {amt_key!r} must be a finite number"
                    fval = float(val)
                    if fval < 0.0 or fval > self.max_amount:
                        return (
                            False,
                            f"parameter {amt_key!r}={fval} violates [0, {self.max_amount}]",
                        )
            if (tool or "") in _SPEND_TOOLS and not found_spend_arg:
                return (
                    False,
                    f"spend tool {tool!r} requires explicit numeric amount under max_amount={self.max_amount}",
                )

        # 2. Check general numeric_bounds constraints (and reject omission for constrained schema params)
        for bound_key, limit in self.numeric_bounds:
            candidate_keys = [bound_key]
            if bound_key.startswith("max_") and len(bound_key) > 4:
                candidate_keys.append(bound_key[4:])
            matched_ck = False
            for ck in candidate_keys:
                if ck in args:
                    matched_ck = True
                    val = args[ck]
                    if not _is_valid_number(val):
                        return False, f"parameter {ck!r} must be a finite number"
                    fval = float(val)
                    if fval < 0.0 or fval > limit:
                        return (
                            False,
                            f"parameter {ck!r}={fval} violates numeric bound [0, {limit}]",
                        )
            if not matched_ck and any(ck in tool_schema_params for ck in candidate_keys):
                return (
                    False,
                    f"tool {tool!r} omitted required numeric-bounded parameter {bound_key!r} <= {limit}",
                )

        # 3. Check allowed_scopes constraint
        if self.allowed_scopes is not None:
            if len(self.allowed_scopes) == 0:
                return False, "allowed_scopes is empty"
            for skey in ("scope", "scopes"):
                if skey in args:
                    sval = args[skey]
                    if isinstance(sval, str):
                        items = [s for s in sval.split() if s] if " " in sval else [sval]
                    elif isinstance(sval, (list, tuple, set, frozenset)):
                        if not all(isinstance(x, str) for x in sval):
                            return False, f"parameter {skey!r} elements must be strings"
                        items = list(sval)
                    else:
                        return False, f"parameter {skey!r} must be string or string list"
                    if not items or not set(items).issubset(self.allowed_scopes):
                        return (
                            False,
                            f"requested {skey}={items} not in allowed_scopes {sorted(self.allowed_scopes)}",
                        )

        # 4. Check allowed_targets constraint (including implicit/explicit target validation)
        if self.allowed_targets is not None:
            if len(self.allowed_targets) == 0:
                return False, "allowed_targets is empty"
            found_target_arg = False
            for tkey in ("target", "targets", "required_targets"):
                if tkey in args:
                    found_target_arg = True
                    tval = args[tkey]
                    if isinstance(tval, str):
                        t_items = [tval]
                    elif isinstance(tval, (list, tuple, set, frozenset)):
                        if not all(isinstance(x, str) for x in tval):
                            return False, f"parameter {tkey!r} elements must be strings"
                        t_items = list(tval)
                    else:
                        return False, f"parameter {tkey!r} must be string or string list"
                    if not t_items or not set(t_items).issubset(self.allowed_targets):
                        return (
                            False,
                            f"requested {tkey}={t_items} not in allowed_targets {sorted(self.allowed_targets)}",
                        )
            if not found_target_arg:
                imp_target = _IMPLICIT_TOOL_TARGETS.get(tool or "")
                if imp_target is not None:
                    if imp_target not in self.allowed_targets:
                        return (
                            False,
                            f"implicit target {imp_target!r} for tool {tool!r} not in allowed_targets {sorted(self.allowed_targets)}",
                        )
                elif (tool or "") in _EXPLICIT_TARGET_TOOLS:
                    return (
                        False,
                        f"tool {tool!r} requires explicit target under allowed_targets {sorted(self.allowed_targets)}",
                    )

        # 5. Check param_whitelist constraints (and reject omission for constrained schema params)
        for pkey, allowed_vals in self.param_whitelist:
            if len(allowed_vals) == 0:
                return False, f"param_whitelist[{pkey!r}] is empty"
            if pkey in args:
                pval = args[pkey]
                if isinstance(pval, str):
                    p_items = [pval]
                elif isinstance(pval, (list, tuple, set, frozenset)):
                    if not all(isinstance(x, str) for x in pval):
                        return False, f"parameter {pkey!r} elements must be strings"
                    p_items = list(pval)
                else:
                    return False, f"parameter {pkey!r} must be string or string list"
                if not p_items or not set(p_items).issubset(allowed_vals):
                    return (
                        False,
                        f"parameter {pkey!r}={p_items} not in whitelist {sorted(allowed_vals)}",
                    )
            elif pkey in tool_schema_params:
                return (
                    False,
                    f"tool {tool!r} omitted required whitelisted parameter {pkey!r} in {sorted(allowed_vals)}",
                )

        return True, "ok"

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "tools": sorted(self.tools),
            "methods": sorted(self.methods),
            "max_amount": self.max_amount,
            "numeric_bounds": {k: v for k, v in self.numeric_bounds},
            "allowed_scopes": sorted(self.allowed_scopes)
            if self.allowed_scopes is not None
            else None,
            "allowed_targets": sorted(self.allowed_targets)
            if self.allowed_targets is not None
            else None,
            "param_whitelist": {k: sorted(vals) for k, vals in self.param_whitelist},
            "max_calls": self.max_calls,
        }
        return data

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PermissionLattice":
        if not isinstance(raw, Mapping):
            raise LatticeError("PermissionLattice JSON must be an object")
        tools = raw.get("tools")
        methods = raw.get("methods")
        if not isinstance(tools, list) or not isinstance(methods, list):
            raise LatticeError("PermissionLattice requires list 'tools' and 'methods'")
        nb_raw = raw.get("numeric_bounds") or {}
        if not isinstance(nb_raw, Mapping):
            raise LatticeError("numeric_bounds must be an object")
        pw_raw = raw.get("param_whitelist") or {}
        if not isinstance(pw_raw, Mapping):
            raise LatticeError("param_whitelist must be an object")

        scopes_raw = raw.get("allowed_scopes")
        targets_raw = raw.get("allowed_targets")

        return cls.create(
            tools=[str(x) for x in tools],
            methods=[str(x) for x in methods],
            max_amount=raw.get("max_amount"),
            numeric_bounds={str(k): float(v) for k, v in nb_raw.items()},
            allowed_scopes=[str(s) for s in scopes_raw] if scopes_raw is not None else None,
            allowed_targets=[str(t) for t in targets_raw] if targets_raw is not None else None,
            param_whitelist={
                str(k): [str(v) for v in vals] for k, vals in pw_raw.items()
            },
            max_calls=int(raw.get("max_calls", 100)),
        )


@dataclass(frozen=True)
class CompositePermission:
    """Disjunctive union of surviving parent branch lattices for Multi-Parent DAGs.

    Under Fagin's multi-path delegation semantics, an action at convergence node C
    is permitted iff AT LEAST ONE surviving unrevoked parent chain authorizes the
    complete call vector (preventing cross-branch Cartesian privilege amplification).
    """

    surviving_branches: Tuple[Tuple[str, PermissionLattice], ...]

    @property
    def effective_tools(self) -> FrozenSet[str]:
        union_set = set()
        for _, lat in self.surviving_branches:
            union_set.update(lat.tools)
        return frozenset(union_set)

    @property
    def effective_methods(self) -> FrozenSet[str]:
        union_set = set()
        for _, lat in self.surviving_branches:
            union_set.update(lat.methods)
        return frozenset(union_set)

    def evaluate(
        self,
        method: str,
        tool: Optional[str] = None,
        arguments: Optional[Mapping[str, Any]] = None,
        branch_call_indices: Optional[Mapping[str, int]] = None,
    ) -> Tuple[bool, List[str], Dict[str, str]]:
        """Return (allowed, satisfying_lineage_paths, rejected_path_reasons)."""
        if not self.surviving_branches:
            return False, [], {"_dag": "no surviving unrevoked parent branches"}

        satisfying: List[str] = []
        reasons: Dict[str, str] = {}
        indices = branch_call_indices or {}

        for path, lattice in self.surviving_branches:
            call_idx = indices.get(path, 1)
            ok, reason = lattice.check_invocation(
                method=method,
                tool=tool,
                arguments=arguments,
                call_index=call_idx,
            )
            if ok:
                satisfying.append(path)
            else:
                reasons[path] = reason

        return len(satisfying) > 0, satisfying, reasons
