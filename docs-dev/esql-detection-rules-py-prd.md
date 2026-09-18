# PRD — Offline ES|QL validation (`esql-detection-rules-py`)

Status: **implementation in progress** via [detection-rules#6499](https://github.com/elastic/detection-rules/pull/6499) + [elastic/esql-detection-rules-py](https://github.com/elastic/esql-detection-rules-py).

Canonical locked decisions + architecture: see the full PRD artifact / canvas **Requirements** tab (source: initial ES|QL parser PRD §0–§17).

## Goal

Ship offline ES|QL parse + schema validation in detection-rules CI/authoring without a live cluster, while keeping remote validation optional for fidelity.

## Consumer contract

| Item | Value |
| --- | --- |
| Import | `import esql` (required, not optional) |
| Pin | `esql-detection-rules-py==0.1.0` (same pattern as `eql==1.0.1`; unpublished until the parser is public) |
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

## Validation evidence (2026-09-17)

| Check | Result |
| --- | --- |
| `esql-detection-rules-py` full pytest | **203 passed** (nested + offline parity + feature gates + ENRICH KEEP) |
| `pytest tests/test_esql_offline.py tests/test_hunt_data.py` | **31 passed** |
| Full ES\|QL corpus (offline load + re-validate) | **228/228** |
| Release branches (parse + feature floors) | **8.19 198, 9.3 214, 9.4 220, 9.5 224 — all green, 0 hygiene** (#6829 dropped 8.19 COMPLETION) |

## Remaining (tracked on canvas)

- Publish `esql-detection-rules-py==0.1.0` to PyPI so CI can install it.
- OSS filing (WG Read, Green List, public-repo issue) — do not file yet.
- When ES grammar adds `EQL()`, enable NestedQuery extraction + fixtures; EQL source command is separate (ES #154780).
- LOOKUP JOIN: parser `Schema(lookups=)` exists; DR does not yet pass lookup-index mappings.

## Non-goals (v1)

- Query execution; nested `QSTR` / `PROMQL` validators; separate grammar packages; Java as default gate.
