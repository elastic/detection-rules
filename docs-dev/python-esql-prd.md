# PRD — Offline ES|QL validation (`python-esql`)

Status: **implementation in progress** via [detection-rules#6499](https://github.com/elastic/detection-rules/pull/6499) + [elastic/python-esql](https://github.com/elastic/python-esql).

## Goal

Ship offline ES|QL parse + schema validation in detection-rules CI/authoring without a live cluster, while keeping remote validation optional for fidelity.

## Consumer contract

| Item | Value |
| --- | --- |
| Import | `import esql` |
| Pin | `python-esql==0.1.1` in `pyproject.toml` (PyPI; not git URL) |
| Grammar host | Versioned modules **inside** the parser package (`esql/_antlr/v8_19_0` … `v9_5_0` + `vlatest`) — same model as EQL feature windows |
| Stack floors | 8.19, 9.3, 9.4, 9.5; tip = ES `main` for pre-GA (e.g. 9.6 until numbered) |
| Nested languages | `KQL()` / `EQL()` via hooks; `QSTR` / `PROMQL` opaque |

## Detection-rules wiring

- `set_esql_config()` builds `esql.ParserConfig` + feature gates + nested parse hooks.
- Nested `KQL()` always uses `normalize_kql_keywords=True` (uppercase `NOT`/`AND`/`OR` parity with Kibana). Top-level kuery rules still honor `RULES_CONFIG.normalize_kql_keywords`.
- `ESQLValidator` is the offline path; remote remains optional.

## Validation evidence (2026-09-14)

| Check | Result |
| --- | --- |
| `python-esql` `make ci` | Pass |
| `pytest tests/test_esql_offline.py` | Pass (nested uppercase KQL included) |
| Full ES\|QL corpus (feature branch) | **226/226** |
| Release branches (parse-only via `validate_release_branches.py`) | **8.19: 200/201**, **9.3: 215/215**, **9.4: 221/221**, **9.5: 225/225** |

### Release-branch note

The single 8.19 failure is `multiple_alerts_llm_by_user_entity.toml`: it uses `COMPLETION … WITH {…}` without `min_stack_version` on the 8.19 line (9.3+ required). On 9.3+ the same rule sets `min_stack_version = "9.3.0"` and passes. That is expected language gating, not a parser bug.

## CI install (staging)

`python-esql` is not yet on PyPI (token scoped to another project). Until publish:

- Vendored snapshot at `lib/esql` (see `lib/esql/VENDOR.md`)
- Pin: `python-esql @ file:./lib/esql` in `pyproject.toml`

## Bake-ins from recent DR ES|QL work

Subquery source groups, flattened `field_extract`, ECS/non-ECS schema paths, memoize/dedupe, KEEP/METADATA semantics, and nested KQL fixes must remain compatible when bumping the parser pin.

## Open-source path (not filing yet)

Prepare private `python-esql` for public launch checklist; preferred public name remains **`python-esql`** (optional `esql-py`). Later: one-commit migration to the public repo. See `python-esql/docs/oss-readiness.md`.

## Non-goals

- Query execution
- Nest-validating PromQL / Lucene `QSTR`
- Shipping grammar versions as separate packages (they live in-parser)
