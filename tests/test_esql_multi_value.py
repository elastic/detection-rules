# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL always-multivalued field compares (AST guardrail).

Hard-fail set = curated high-risk fields plus ECS ``normalize: ["array"]`` fields that
match always-multi patterns (``.args``, ``.roles``, ``related.*``, email addresses,
``host.ip``, ``dns.resolved_ip``). ``event.category`` / ``event.type`` stay excluded —
array-capable but usually cardinality 1.

Walks every production ES|QL rule AST for unprotected ``==`` / ``!=`` / ``in`` /
``like`` / ``rlike``. ``MV_EXPAND`` of the field, ``MV_CONTAINS``, or ``MV_INTERSECTS``
counts as protected.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import esql
from esql import ast

from detection_rules.ecs import get_multivalued_fields

from .base import BaseRuleTest

# Non-ECS / corpus extras always included even when absent from ECS flat.
_CURATED_ALWAYS_MULTI = frozenset(
    {
        "process.args",
        "process.parent.args",
        "user.roles",
        "user.target.roles",
        "source.user.roles",
        "destination.user.roles",
        "host.ip",
        "dns.resolved_ip",
        "email.from.address",
        "email.to.address",
        "email.cc.address",
        "email.bcc.address",
        "kibana.alert.rule.threat.tactic.name",
        "kibana.alert.rule.threat.technique.id",
        "related.ip",
        "related.user",
        "related.hash",
        "related.hosts",
    }
)

# ECS normalize:array but usually length-1 — do not hard-fail.
_ECS_HARD_FAIL_EXCLUDE = frozenset(
    {
        "event.category",
        "event.type",
    }
)

_COMPARE_OPS = frozenset({"==", "!=", "in", "not in", "not_in"})
_LIKE_FUNCS = frozenset({"like", "not_like", "rlike", "not_rlike"})
_MV_PROTECT_FUNCS = frozenset({"mv_contains", "mv_intersects"})

# Shrink as rules are fixed; do not grow without review. Paths relative to repo `rules/`.
KNOWN_UNPROTECTED: dict[str, frozenset[str]] = {
    "rules/linux/defense_evasion_base64_decoding_activity.toml": frozenset({"process.args"}),
    "rules/network/initial_access_fortigate_admin_login_multi_srcip.toml": frozenset({"source.user.roles"}),
    "rules/network/initial_access_newly_observed_fortigate_admin_logon.toml": frozenset({"source.user.roles"}),
    "rules/integrations/microsoft_exchange_online_message_trace/initial_access_azure_monitor_callback_phishing_email.toml": frozenset(
        {"email.from.address"}
    ),
    "rules/cross-platform/multiple_alerts_same_tactic_by_host.toml": frozenset(
        {"kibana.alert.rule.threat.tactic.name"}
    ),
}


def _ecs_always_multi_augment(ecs_mv: frozenset[str]) -> frozenset[str]:
    """Pull high-risk always-multi candidates from ECS normalize:array."""
    out: set[str] = set()
    for name in ecs_mv:
        if name in _ECS_HARD_FAIL_EXCLUDE:
            continue
        if (
            name.endswith((".args", ".roles"))
            or name.startswith("related.")
            or (name.startswith("email.") and name.endswith(".address"))
            or name in {"host.ip", "dns.resolved_ip"}
        ):
            out.add(name)
    return frozenset(out)


@lru_cache(maxsize=1)
def hard_fail_multivalue_fields() -> frozenset[str]:
    """Curated always-multi plus ECS-augmented high-risk array fields."""
    return frozenset(_CURATED_ALWAYS_MULTI | _ecs_always_multi_augment(get_multivalued_fields()))


def _is_always_multi(name: str) -> bool:
    hard = hard_fail_multivalue_fields()
    if name in hard:
        return True
    return any(name.endswith(suffix) for suffix in (".roles", ".user.roles", ".user.target.roles"))


def _column_name(node: object) -> str | None:
    return node.name if isinstance(node, ast.ColumnRef) else None


def _norm_func_name(name: str | None) -> str:
    return (name or "").lower().replace(" ", "_")


def unprotected_always_multi_compares(query: str) -> set[str]:
    """Return always-multi fields used in scalar compares/likes without MV protection."""
    tree = esql.parse_query(query)
    expanded: set[str] = set()
    unprotected: set[str] = set()

    def flag(field: str | None, *, mv_protected: bool) -> None:
        if field and _is_always_multi(field) and field not in expanded and not mv_protected:
            unprotected.add(field)

    def walk_function(node: ast.FunctionCall, *, mv_protected: bool) -> None:
        name = _norm_func_name(node.name)
        args = list(node.args or ())
        if name in _MV_PROTECT_FUNCS:
            for arg in args:
                walk(arg, mv_protected=True)
            return
        if name == "not" and args:
            walk(args[0], mv_protected=mv_protected)
            return
        if name in _LIKE_FUNCS and args:
            flag(_column_name(args[0]), mv_protected=mv_protected)
        for arg in args:
            walk(arg, mv_protected=mv_protected)

    def walk(node: object | None, *, mv_protected: bool = False) -> None:
        if node is None:
            return
        if isinstance(node, ast.FunctionCall):
            walk_function(node, mv_protected=mv_protected)
            return
        if isinstance(node, ast.BinaryExpr):
            op = (node.op or "").lower().strip()
            if op in _COMPARE_OPS:
                for side in (node.left, node.right):
                    flag(_column_name(side), mv_protected=mv_protected)
            walk(node.left, mv_protected=mv_protected)
            walk(node.right, mv_protected=mv_protected)
            return
        if isinstance(node, ast.BaseNode):
            for child in node:
                if isinstance(child, ast.BaseNode) and child is not node:
                    walk(child, mv_protected=mv_protected)

    for cmd in tree.commands:
        if isinstance(cmd, ast.MvExpandCommand):
            field = getattr(cmd, "field", None)
            if isinstance(field, str) and field:
                expanded.add(field)
            elif isinstance(field, ast.ColumnRef):
                expanded.add(field.name)
            continue
        if isinstance(cmd, ast.WhereCommand):
            walk(cmd.predicate)

    return unprotected


def _repo_relative(path: Path | None) -> str:
    if path is None:
        return ""
    parts = path.parts
    try:
        idx = parts.index("rules")
    except ValueError:
        return str(path)
    return str(Path(*parts[idx:]))


def test_mv_expand_protects_only_following_compares() -> None:
    """MV_EXPAND covers a later compare of that field and not an earlier one."""
    early = """
    FROM logs-*
    | WHERE process.args == "x"
    | MV_EXPAND process.args
    | KEEP process.args
    """
    late = """
    FROM logs-*
    | MV_EXPAND process.args
    | WHERE process.args == "x"
    | KEEP process.args
    """
    assert "process.args" in unprotected_always_multi_compares(early)
    assert "process.args" not in unprotected_always_multi_compares(late)


class TestEsqlAlwaysMultiFields(BaseRuleTest):
    """Iterate all production ES|QL rules like test_all_rules."""

    def test_hard_fail_set_uses_ecs_augment(self) -> None:
        """Curated ECS fields stay in the hard-fail set; noisy category/type stay out."""
        ecs_mv = get_multivalued_fields()
        hard = hard_fail_multivalue_fields()

        self.assertTrue({"process.args", "user.roles", "host.ip"} <= ecs_mv)
        self.assertTrue({"process.args", "user.roles", "host.ip"} <= hard)
        self.assertTrue({"event.category", "event.type"} <= ecs_mv)
        self.assertFalse({"event.category", "event.type"} & hard)
        # Non-ECS curated fields still hard-fail.
        self.assertIn("kibana.alert.rule.threat.tactic.name", hard)
        # ECS augment pulls sibling always-multi fields (e.g. other *.args).
        self.assertTrue(any(f.endswith(".args") and f not in _CURATED_ALWAYS_MULTI for f in hard))

    def test_all_esql_rules_multivalue_compares(self) -> None:
        """Parse every ES|QL rule and flag unprotected always-multi field compares."""
        unexpected: list[str] = []
        seen_exceptions: set[str] = set()

        for rule in self.all_rules:
            if getattr(rule.contents.data, "language", None) != "esql":
                continue

            rel = _repo_relative(rule.path)
            with self.subTest(rule=self.rule_str(rule), path=rel):
                hits = unprotected_always_multi_compares(rule.contents.data.query)
                expected = set(KNOWN_UNPROTECTED.get(rel, ()))

                if hits and rel not in KNOWN_UNPROTECTED:
                    unexpected.append(f"{rel}: {sorted(hits)}")
                elif hits != expected:
                    unexpected.append(f"{rel}: got {sorted(hits)}, expected {sorted(expected)}")
                if rel in KNOWN_UNPROTECTED:
                    seen_exceptions.add(rel)

        missing = sorted(set(KNOWN_UNPROTECTED) - seen_exceptions)
        self.assertFalse(
            unexpected or missing,
            "ES|QL always-multi field compares changed.\n"
            "unexpected/changed:\n  " + "\n  ".join(unexpected or ["(none)"]) + "\n"
            "known exceptions not seen (fixed?):\n  " + "\n  ".join(missing or ["(none)"]),
        )

    def test_mv_expand_and_mv_contains_protect(self) -> None:
        """Synthetic cases for the AST walker."""
        self.assertEqual(
            unprotected_always_multi_compares('FROM logs-* | WHERE process.args == "enc" | KEEP _id'),
            {"process.args"},
        )
        self.assertEqual(
            unprotected_always_multi_compares(
                """
                FROM logs-*
                | MV_EXPAND process.args
                | WHERE process.args == "enc"
                | KEEP _id
                """
            ),
            set(),
        )
        self.assertEqual(
            unprotected_always_multi_compares('FROM logs-* | WHERE mv_contains(process.args, "enc") | KEEP _id'),
            set(),
        )
        self.assertEqual(
            unprotected_always_multi_compares(
                'FROM logs-* | WHERE mv_intersects(process.args, ["enc", "dec"]) | KEEP _id'
            ),
            set(),
        )
        self.assertEqual(
            unprotected_always_multi_compares('FROM logs-* | WHERE event.category == "process" | KEEP _id'),
            set(),
        )
