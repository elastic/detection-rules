# PRD — Offline ES|QL validation (`python-esql`)

Status: **implementation in progress** via [detection-rules#6499](https://github.com/elastic/detection-rules/pull/6499) + [elastic/python-esql](https://github.com/elastic/python-esql).

Canonical locked decisions + architecture: see the full PRD artifact / canvas **Requirements** tab (source: initial `python-esql` PRD §0–§17).

## Goal

Ship offline ES|QL parse + schema validation in detection-rules CI/authoring without a live cluster, while keeping remote validation optional for fidelity.

## Consumer contract

| Item | Value |
| --- | --- |
| Import | `import esql` (required, not optional) |
| Pin | `python-esql==0.1.1` from PyPI when published (staging: `file:./lib/esql`) |
| Grammar host | Versioned modules **inside** the parser (`esql/_antlr/v8_19_0` … `v9_5_0` + `vlatest`) |
| Stack floors | Current window: 8.19, 9.3, 9.4, 9.5 (+ tip); follow `stack-schema-map.yaml` |
| Nested languages | `KQL()` / `EQL()`: parse hooks + **schema checks** via native `kql`/`eql`; `QSTR` / `PROMQL` opaque |

## Nested `KQL()` / `EQL()` (PRD §5.7)

Two layers (MVP for KQL; EQL hook ready for grammar):

1. **Syntax** — `set_esql_config` installs `kql_parse` / `eql_parse` (KQL always `normalize_kql_keywords=True`).
2. **Schema** — `ESQLValidator` re-validates nested payloads against each `ValidationTarget` schema (same plan as outer ES|QL), using KQL/EQL schema behavior — not by treating the fragment as a standalone rule.
3. **Metadata** — `unique_fields` unions nested KQL/EQL field names into the outer set.

`EQL()` grammar may not ship in ES|QL yet; keep the same pipeline ready. A future `EQL` **source command** (opaque) is a separate shape from boolean `EQL()`.

## Detection-rules wiring

- `set_esql_config()` → `ParserConfig` + hybrid `ESQL_FEATURES` + DR overrides + nested hooks.
- `ESQLValidator` = default offline path; remote optional (`DR_REMOTE_ESQL_VALIDATION`).
- Unset `min_stack_version` → validate full supported window.

## Validation evidence (2026-09-14+)

| Check | Result |
| --- | --- |
| `python-esql` `make ci` | Pass |
| `pytest tests/test_esql_offline.py` | Pass (nested KQL + eql hook prep) |
| Full ES\|QL corpus (feature branch) | **226/226** |
| Release branches (parse-only) | **8.19: 200/201**, **9.3–9.5: green** |

## Remaining (tracked on canvas Requirements tab)

- Publish PyPI `python-esql==0.1.1` and drop vendored `file:` pin.
- Complete regex → AST retirement where still present.
- Analyzer depth / remote fidelity golden diffs (optional).
- OSS filing (WG Read, Green List, public-repo issue) — files staged, do not file yet.
- When ES grammar adds `EQL()`, enable NestedQuery extraction + fixtures.

## Non-goals (v1)

- Query execution; nested `QSTR` / `PROMQL` validators; separate grammar packages; Java as default gate.
