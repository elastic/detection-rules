# esql-validator

A long-running JVM daemon that exposes Elasticsearch's own ES|QL parser and
verifier over a tiny line-delimited JSON protocol on stdin/stdout. It is the
Java half of the `detection_rules.esql_parser` Python module — the Python
side spawns it as a subprocess and validates rule queries against it without
needing an Elasticsearch cluster.

Use it when you want the same `ParsingException` / `VerificationException`
errors a real cluster would raise (line and column included), but you don't
want to stand up Elasticsearch or Kibana just to syntax-check a query.

## What it does

For each request, the daemon:

1. **Parses** the query with [`EsqlParser`](https://github.com/elastic/elasticsearch/blob/main/x-pack/plugin/esql/src/main/java/org/elasticsearch/xpack/esql/parser/EsqlParser.java).
2. **Verifies** the resulting `LogicalPlan` with the same `Analyzer` +
   `Verifier` used by [`VerifierTests`](https://github.com/elastic/elasticsearch/blob/main/x-pack/plugin/esql/src/test/java/org/elasticsearch/xpack/esql/analysis/VerifierTests.java),
   wired up with the index mappings, lookup mappings, and enrich policies
   supplied in the request.

Returns either the analyzed plan as text, or structured `parse_error` /
`verify_error` diagnostics with line and column numbers.

## Requirements

- JDK 21 on `PATH` (matches what Elasticsearch is built against).
- A local checkout of [`elastic/elasticsearch`](https://github.com/elastic/elasticsearch).
  Default location is `/tmp/elasticsearch`; override with `ES_HOME=…`.

## Build

```sh
ES_HOME=/path/to/elasticsearch ./build.sh
```

This:

1. Invokes Elasticsearch's own gradle to compile `:x-pack:plugin:esql` and
   resolve its full compile/runtime classpath.
2. Writes `build/classpath.txt` (colon-separated jar paths).
3. Compiles the daemon sources against that classpath.
4. Packages them as `build/esql-validator.jar` (manifest sets the main class).

First build is slow because gradle has to compile the ES plugins; subsequent
builds reuse the gradle build cache and finish in seconds.

## Run manually

```sh
java -cp "$(cat build/classpath.txt):build/esql-validator.jar" \
     co.elastic.detectionrules.esqlvalidator.Main
```

Then send one JSON request per line on stdin:

```json
{"id":"1","query":"FROM logs | WHERE foo == 1","indices":{"logs":{"properties":{"foo":{"type":"integer"}}}}}
```

You'll get one response per line on stdout. See `Main.java` for the request
and response shape.

## Wire protocol

**Request**

| Field             | Type                              | Notes                                                                                  |
|-------------------|-----------------------------------|----------------------------------------------------------------------------------------|
| `id`              | string                            | echoed back in the response                                                            |
| `query`           | string                            | the ES\|QL query                                                                       |
| `indices`         | `{pattern: es_mapping}`           | mappings for `FROM` targets, e.g. `{"logs": {"properties": {"foo": {"type": "long"}}}}` |
| `lookup_indices`  | `{name: es_mapping}`              | mappings for `LOOKUP JOIN` targets (loaded in `LOOKUP` index mode)                     |
| `enrich_policies` | list of policy descriptors        | `{name, policy_type, match_field, index, mapping}`                                     |
| `params`          | list                              | values for positional `?` parameters                                                   |
| `shutdown`        | boolean                           | if true, daemon exits after responding                                                 |
| `ping`            | boolean                           | if true, daemon responds with `{"status":"pong"}`                                      |

**Response**

| `status`         | Other fields                                                |
|------------------|-------------------------------------------------------------|
| `ok`             | `plan` — analyzed logical plan as text                      |
| `parse_error`    | `errors[]` — `{type, message, line, column}`                |
| `verify_error`   | `errors[]` — one entry per Verifier diagnostic              |
| `request_error`  | `message` — malformed JSON or missing required field        |
| `internal_error` | `message` — uncaught exception while serializing a response |

## Python interface

```python
from detection_rules.esql_parser import EsqlValidator

with EsqlValidator() as v:
    result = v.validate(
        "FROM logs | WHERE foo == 1 | LIMIT 5",
        indices={"logs": {"properties": {"foo": {"type": "integer"}}}},
    )
    if not result.ok:
        for err in result.errors:
            print(f"{err.type} at {err.line}:{err.column}: {err.message}")
```

The Python class spawns the daemon once and reuses it across calls, so JVM
startup cost is paid only on the first `validate(...)`. If the JAR is missing
and `build_if_missing=True` (the default), it'll invoke `build.sh` for you.
