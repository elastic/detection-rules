/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package co.elastic.detectionrules.esqlvalidator;

import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.xcontent.NamedXContentRegistry;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.XContentParser;
import org.elasticsearch.xcontent.XContentParserConfiguration;
import org.elasticsearch.xcontent.json.JsonXContent;
import org.elasticsearch.xpack.esql.VerificationException;
import org.elasticsearch.xpack.esql.analysis.Analyzer;
import org.elasticsearch.xpack.esql.inference.InferenceSettings;
import org.elasticsearch.xpack.esql.parser.EsqlConfig;
import org.elasticsearch.xpack.esql.parser.EsqlParser;
import org.elasticsearch.xpack.esql.parser.ParsingException;
import org.elasticsearch.xpack.esql.parser.QueryParam;
import org.elasticsearch.xpack.esql.parser.QueryParams;
import org.elasticsearch.xpack.esql.plan.logical.LogicalPlan;
import org.elasticsearch.xpack.esql.core.type.DataType;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Long-running daemon that validates ES|QL queries via line-delimited JSON over
 * stdin/stdout. One request per stdin line, one response per stdout line.
 *
 * <p>Request shape:
 * <pre>{@code
 *   {"id": "1",
 *    "query": "FROM logs | WHERE foo == 1",
 *    "indices": {"logs": {"properties": {"foo": {"type": "integer"}}}},
 *    "lookup_indices": {...},
 *    "enrich_policies": [{"name": "p1", "policy_type": "match", "match_field": "ip",
 *                         "index": "idx", "mapping": {...}}],
 *    "params": [1, "x"]}
 * }</pre>
 *
 * <p>Response shape on success:
 * <pre>{@code {"id": "1", "status": "ok", "plan": "..."}}</pre>
 *
 * <p>Response shape on failure:
 * <pre>{@code {"id": "1", "status": "parse_error", "errors": [{"message": "...", "line": 1, "column": 5}]}}</pre>
 *
 * <p>To shut down: send {@code {"shutdown": true}} or close stdin.
 */
public final class Main {

    public static void main(String[] args) throws Exception {
        // Replace stdout so we can keep it for protocol output. Anything written by
        // ES internals or our own logging must go to stderr.
        PrintStream protocolOut = System.out;
        System.setOut(System.err);

        // ES code paths require the logging SPI to be wired up before any
        // class with a static `LogManager.getLogger(...)` field is loaded.
        org.elasticsearch.common.logging.LogConfigurator.configureESLogging();

        AnalyzerFactory analyzerFactory = new AnalyzerFactory();
        EsqlParser parser = new EsqlParser(new EsqlConfig(analyzerFactory.functionRegistry()));
        InferenceSettings inference = new InferenceSettings(Settings.EMPTY);

        // Handshake — Python wrapper waits for this before sending requests.
        protocolOut.println("{\"status\":\"ready\"}");
        protocolOut.flush();

        try (BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                String response = handle(line, parser, inference, analyzerFactory);
                protocolOut.println(response);
                protocolOut.flush();
                if (response.contains("\"status\":\"bye\"")) {
                    return;
                }
            }
        }
    }

    private static String handle(String line, EsqlParser parser, InferenceSettings inference, AnalyzerFactory analyzerFactory) {
        Request req;
        try {
            req = Request.parse(line);
        } catch (Exception e) {
            return write(b -> {
                b.field("status", "request_error");
                b.field("message", e.getClass().getSimpleName() + ": " + e.getMessage());
            });
        }

        if (req.shutdown) {
            return write(b -> b.field("id", req.id).field("status", "bye"));
        }
        if (req.ping) {
            return write(b -> b.field("id", req.id).field("status", "pong"));
        }
        if (req.query == null) {
            return write(b -> b.field("id", req.id).field("status", "request_error")
                .field("message", "missing 'query' field"));
        }

        // Stage 1: parse.
        LogicalPlan parsed;
        try {
            parsed = parser.parseQuery(req.query, buildParams(req.params), inference);
        } catch (ParsingException pe) {
            return errorResponse(req.id, "parse_error", "ParsingException",
                pe.getErrorMessage(), pe.getLineNumber(), pe.getColumnNumber());
        } catch (Exception e) {
            return errorResponse(req.id, "parse_error", e.getClass().getSimpleName(),
                e.getMessage(), -1, -1);
        }

        // Stage 2: verify (analyze).
        try {
            Analyzer analyzer = analyzerFactory.build(new AnalyzerFactory.ResolutionInputs(
                req.indices, req.lookupIndices, req.enrichPolicies));
            LogicalPlan analyzed = analyzer.analyze(parsed);
            String planText = analyzed.toString();
            return write(b -> {
                b.field("id", req.id);
                b.field("status", "ok");
                b.field("plan", planText);
            });
        } catch (VerificationException ve) {
            return verifyErrorResponse(req.id, ve.getMessage());
        } catch (ParsingException pe) {
            return errorResponse(req.id, "verify_error", "ParsingException",
                pe.getErrorMessage(), pe.getLineNumber(), pe.getColumnNumber());
        } catch (Exception e) {
            return errorResponse(req.id, "verify_error", e.getClass().getSimpleName(),
                e.getMessage() == null ? e.toString() : e.getMessage(), -1, -1);
        }
    }

    private static QueryParams buildParams(List<Object> params) {
        if (params == null || params.isEmpty()) {
            return new QueryParams();
        }
        List<QueryParam> out = new ArrayList<>(params.size());
        for (Object v : params) {
            DataType type = DataType.fromJava(v);
            if (type == null) {
                type = DataType.KEYWORD;
            }
            out.add(new QueryParam(null, v, type, org.elasticsearch.xpack.esql.parser.ParserUtils.ParamClassification.VALUE));
        }
        return new QueryParams(out);
    }

    private static String errorResponse(String id, String status, String type, String message, int line, int column) {
        return write(b -> {
            b.field("id", id);
            b.field("status", status);
            b.startArray("errors");
            b.startObject();
            b.field("type", type);
            b.field("message", message);
            if (line >= 0) {
                b.field("line", line);
            }
            if (column >= 0) {
                b.field("column", column);
            }
            b.endObject();
            b.endArray();
        });
    }

    /** Split a VerificationException's multi-error message into one error entry per line. */
    private static String verifyErrorResponse(String id, String message) {
        return write(b -> {
            b.field("id", id);
            b.field("status", "verify_error");
            b.startArray("errors");
            for (String entry : splitVerifyMessage(message)) {
                b.startObject();
                b.field("type", "VerificationException");
                // Try to peel "line L:C: ..." into structured fields.
                int line = -1, col = -1;
                String text = entry;
                if (entry.startsWith("line ")) {
                    int colon1 = entry.indexOf(':', 5);
                    int colon2 = colon1 > 0 ? entry.indexOf(':', colon1 + 1) : -1;
                    if (colon1 > 0 && colon2 > 0) {
                        try {
                            line = Integer.parseInt(entry.substring(5, colon1));
                            col = Integer.parseInt(entry.substring(colon1 + 1, colon2));
                            text = entry.substring(colon2 + 1).trim();
                        } catch (NumberFormatException ignore) {}
                    }
                }
                b.field("message", text);
                if (line >= 0) {
                    b.field("line", line);
                }
                if (col >= 0) {
                    b.field("column", col);
                }
                b.endObject();
            }
            b.endArray();
        });
    }

    private static List<String> splitVerifyMessage(String message) {
        // Verifier messages look like: "Found N problem(s)\nline 1:5: foo\nline 1:10: bar"
        // We split on every "\nline " (or leading "line ") and trim.
        List<String> out = new ArrayList<>();
        int idx = message.indexOf("\nline ");
        if (idx < 0) {
            out.add(message.startsWith("line ") ? message : message);
            return out;
        }
        // Drop the "Found N problem(s)" preamble.
        String rest = message.substring(idx + 1);
        for (String part : rest.split("\\nline ")) {
            String trimmed = part.startsWith("line ") ? part.substring(5).trim() : part.trim();
            // Re-add "line " prefix if it isn't there, so downstream parser can find it.
            out.add(trimmed.matches("^\\d+:\\d+:.*") ? "line " + trimmed : trimmed);
        }
        return out;
    }

    @FunctionalInterface
    private interface Writer {
        void write(XContentBuilder b) throws Exception;
    }

    private static String write(Writer w) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (XContentBuilder b = new XContentBuilder(JsonXContent.jsonXContent, baos)) {
                b.startObject();
                w.write(b);
                b.endObject();
            }
            return baos.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Fall back to a hand-rolled error response we know is valid.
            return "{\"status\":\"internal_error\",\"message\":\""
                + e.getClass().getSimpleName() + ": " + (e.getMessage() == null ? "" : e.getMessage().replace("\"", "'"))
                + "\"}";
        }
    }

    /** Parsed request fields. */
    static final class Request {
        String id;
        String query;
        Map<String, Map<String, Object>> indices;
        Map<String, Map<String, Object>> lookupIndices;
        List<AnalyzerFactory.EnrichPolicyInput> enrichPolicies;
        List<Object> params;
        boolean shutdown;
        boolean ping;

        @SuppressWarnings("unchecked")
        static Request parse(String line) throws Exception {
            byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
            try (XContentParser p = JsonXContent.jsonXContent.createParser(
                    XContentParserConfiguration.EMPTY.withRegistry(NamedXContentRegistry.EMPTY),
                    new BytesArray(bytes).streamInput())) {
                Map<String, Object> raw = p.map();
                Request r = new Request();
                Object idObj = raw.get("id");
                r.id = idObj == null ? null : String.valueOf(idObj);
                r.query = (String) raw.get("query");
                Object shutdownObj = raw.get("shutdown");
                r.shutdown = shutdownObj instanceof Boolean && (Boolean) shutdownObj;
                Object pingObj = raw.get("ping");
                r.ping = pingObj instanceof Boolean && (Boolean) pingObj;
                r.indices = castStringMapOfMap(raw.get("indices"));
                r.lookupIndices = castStringMapOfMap(raw.get("lookup_indices"));
                Object enrich = raw.get("enrich_policies");
                if (enrich instanceof List<?> list) {
                    r.enrichPolicies = new ArrayList<>();
                    for (Object o : list) {
                        if (o instanceof Map<?, ?> m) {
                            Map<String, Object> em = (Map<String, Object>) m;
                            r.enrichPolicies.add(new AnalyzerFactory.EnrichPolicyInput(
                                (String) em.get("name"),
                                (String) em.getOrDefault("policy_type", "match"),
                                (String) em.get("match_field"),
                                (String) em.get("index"),
                                em.get("mapping") instanceof Map<?, ?> mm ? (Map<String, Object>) mm : Map.of()
                            ));
                        }
                    }
                }
                Object params = raw.get("params");
                if (params instanceof List<?> pl) {
                    r.params = new ArrayList<>(pl);
                }
                return r;
            }
        }

        @SuppressWarnings("unchecked")
        private static Map<String, Map<String, Object>> castStringMapOfMap(Object o) {
            if (o instanceof Map<?, ?> m) {
                Map<String, Map<String, Object>> out = new LinkedHashMap<>();
                for (Map.Entry<?, ?> e : m.entrySet()) {
                    if (e.getValue() instanceof Map<?, ?> v) {
                        out.put(String.valueOf(e.getKey()), (Map<String, Object>) v);
                    }
                }
                return out;
            }
            return null;
        }
    }
}
