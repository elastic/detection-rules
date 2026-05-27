/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package co.elastic.detectionrules.esqlvalidator;

import org.elasticsearch.TransportVersion;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.IndexMode;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.xpack.esql.analysis.Analyzer;
import org.elasticsearch.xpack.esql.analysis.AnalyzerContext;
import org.elasticsearch.xpack.esql.analysis.EnrichResolution;
import org.elasticsearch.xpack.esql.analysis.UnmappedResolution;
import org.elasticsearch.xpack.esql.analysis.Verifier;
import org.elasticsearch.xpack.esql.core.tree.Source;
import org.elasticsearch.xpack.esql.core.type.EsField;
import org.elasticsearch.xpack.esql.enrich.ResolvedEnrichPolicy;
import org.elasticsearch.xpack.esql.expression.function.EsqlFunctionRegistry;
import org.elasticsearch.xpack.esql.expression.promql.function.PromqlFunctionRegistry;
import org.elasticsearch.xpack.esql.index.EsIndex;
import org.elasticsearch.xpack.esql.index.IndexResolution;
import org.elasticsearch.xpack.esql.inference.InferenceResolution;
import org.elasticsearch.xpack.esql.plan.IndexPattern;
import org.elasticsearch.xpack.esql.plan.logical.Enrich;
import org.elasticsearch.xpack.esql.session.Configuration;
import org.elasticsearch.xpack.esql.telemetry.Metrics;
import org.elasticsearch.xpack.esql.plugin.QueryPragmas;
import org.elasticsearch.xpack.esql.plan.QuerySettings;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Assembles an {@link Analyzer} from a request payload's resolutions
 * (index mappings, lookup mappings, enrich policies, etc.).
 *
 * <p>The function registry, license state, and verifier are created once at
 * construction and reused across requests. Per-request resolutions are passed
 * into {@link #build(ResolutionInputs)}.
 */
final class AnalyzerFactory {

    private final EsqlFunctionRegistry functionRegistry = new EsqlFunctionRegistry();
    private final PromqlFunctionRegistry promqlFunctionRegistry = new PromqlFunctionRegistry();
    private final XPackLicenseState licenseState = new XPackLicenseState(() -> System.currentTimeMillis());
    private final Verifier verifier = new Verifier(
        new Metrics(functionRegistry, /*isSnapshot*/ true, /*isServerless*/ true),
        licenseState
    );

    EsqlFunctionRegistry functionRegistry() {
        return functionRegistry;
    }

    record ResolutionInputs(
        Map<String, Map<String, Object>> indices,
        Map<String, Map<String, Object>> lookupIndices,
        List<EnrichPolicyInput> enrichPolicies
    ) {}

    record EnrichPolicyInput(
        String name,
        String policyType,
        String matchField,
        String index,
        Map<String, Object> mapping
    ) {}

    Analyzer build(ResolutionInputs inputs) {
        Map<IndexPattern, IndexResolution> indexResolutions = new HashMap<>();
        if (inputs.indices() != null) {
            for (Map.Entry<String, Map<String, Object>> e : inputs.indices().entrySet()) {
                // The ES|QL parser canonicalizes multi-pattern FROM clauses by joining
                // with "," (no whitespace) — see IdentifierBuilder.visitIndexPattern.
                // IndexPattern.equals is a strict string compare, so we must match that
                // canonical form or the analyzer's resolution lookup misses and emits
                // "[none specified]". Accept caller keys with arbitrary whitespace and
                // normalize here for robustness.
                String key = e.getKey().replaceAll("\\s*,\\s*", ",").trim();
                indexResolutions.put(new IndexPattern(Source.EMPTY, key), indexResolution(key, e.getValue(), IndexMode.STANDARD));
            }
        }

        Map<String, IndexResolution> lookupResolutions = new HashMap<>();
        if (inputs.lookupIndices() != null) {
            for (Map.Entry<String, Map<String, Object>> e : inputs.lookupIndices().entrySet()) {
                lookupResolutions.put(e.getKey(), indexResolution(e.getKey(), e.getValue(), IndexMode.LOOKUP));
            }
        }

        EnrichResolution enrichResolution = new EnrichResolution();
        if (inputs.enrichPolicies() != null) {
            for (EnrichPolicyInput p : inputs.enrichPolicies()) {
                IndexResolution ir = indexResolution(p.index(), p.mapping(), IndexMode.STANDARD);
                List<String> enrichFields = new ArrayList<>(ir.get().mapping().keySet());
                enrichFields.remove(p.matchField());
                enrichResolution.addResolvedPolicy(
                    p.name(),
                    Enrich.Mode.ANY,
                    new ResolvedEnrichPolicy(p.matchField(), p.policyType(), enrichFields, Map.of("", p.index()), ir.get().mapping())
                );
            }
        }

        Configuration cfg = buildConfiguration();
        AnalyzerContext ctx = new AnalyzerContext(
            cfg,
            functionRegistry,
            promqlFunctionRegistry,
            indexResolutions,
            lookupResolutions,
            enrichResolution,
            InferenceResolution.builder().build(),
            TransportVersion.current(),
            QuerySettings.UNMAPPED_FIELDS.defaultValue()
        );
        return new Analyzer(ctx, verifier);
    }

    private static IndexResolution indexResolution(String name, Map<String, Object> mapping, IndexMode mode) {
        Map<String, EsField> fields = MappingLoader.fromProperties(mapping);
        return IndexResolution.valid(new EsIndex(name, fields, Map.of(name, mode), Map.of(), Map.of()));
    }

    private static Configuration buildConfiguration() {
        return new Configuration(
            java.time.ZoneOffset.UTC,
            Instant.now(),
            Locale.US,
            null,
            null,
            new QueryPragmas(Settings.EMPTY),
            1000,
            1000,
            null,
            false,
            Map.of(),
            System.nanoTime(),
            false,
            1000,
            1000,
            null,
            null,
            Map.of()
        );
    }
}
