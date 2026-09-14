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
| `python-esql` `make ci` | Pass (83 tests) |
| `pytest tests/test_esql_offline.py` | 12+ tests pass |
| Full ES\|QL corpus via `scripts/e2e_detection_rules_corpus.py` | **226/226** |
| Negative syntax / nested KQL failures | Fail as expected |

## Bake-ins from recent DR ES|QL work

Subquery source groups, flattened `field_extract`, ECS/non-ECS schema paths, memoize/dedupe, KEEP/METADATA semantics, and nested KQL fixes must remain compatible when bumping the parser pin.

## Open-source path (not filing yet)

Prepare private `python-esql` for public launch checklist; preferred public name remains **`python-esql`** (optional `esql-py`). Later: one-commit migration to the public repo. See `python-esql/docs/oss-readiness.md`.

## Non-goals

- Query execution
- Nest-validating PromQL / Lucene `QSTR`
- Shipping grammar versions as separate packages (they live in-parser)
