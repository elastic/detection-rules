/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package co.elastic.detectionrules.esqlvalidator;

import org.elasticsearch.index.mapper.TimeSeriesParams;
import org.elasticsearch.xpack.esql.core.type.DataType;
import org.elasticsearch.xpack.esql.core.type.DateEsField;
import org.elasticsearch.xpack.esql.core.type.EsField;
import org.elasticsearch.xpack.esql.core.type.KeywordEsField;
import org.elasticsearch.xpack.esql.core.type.TextEsField;
import org.elasticsearch.xpack.esql.core.type.UnsupportedEsField;
import org.elasticsearch.xpack.esql.type.EsqlDataTypeRegistry;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyMap;
import static org.elasticsearch.xpack.esql.core.type.DataType.DATETIME;
import static org.elasticsearch.xpack.esql.core.type.DataType.KEYWORD;
import static org.elasticsearch.xpack.esql.core.type.DataType.OBJECT;
import static org.elasticsearch.xpack.esql.core.type.DataType.TEXT;
import static org.elasticsearch.xpack.esql.core.type.DataType.UNSUPPORTED;

/**
 * Converts a parsed ES index mapping (in standard `{"properties": {...}}` form)
 * into the internal {@link EsField} map used by the ES|QL analyzer.
 *
 * <p>This is a copy of the logic in {@code LoadMapping} from the ES test
 * fixtures, but operates on a pre-parsed {@code Map<String,Object>} so we don't
 * have to depend on the test-fixtures source set (which pulls in JUnit).
 */
final class MappingLoader {

    private MappingLoader() {}

    @SuppressWarnings("unchecked")
    static Map<String, EsField> fromProperties(Map<String, Object> mapping) {
        if (mapping == null || mapping.isEmpty()) {
            return emptyMap();
        }
        Object props = mapping.get("properties");
        if (props == null && mapping.values().stream().anyMatch(v -> v instanceof Map && ((Map<?, ?>) v).containsKey("type"))) {
            // Allow the caller to omit the wrapper "properties" key.
            props = mapping;
        }
        if (props instanceof Map<?, ?> raw) {
            return startWalking((Map<String, Object>) raw);
        }
        return emptyMap();
    }

    private static Map<String, EsField> startWalking(Map<String, Object> mapping) {
        Map<String, EsField> types = new LinkedHashMap<>();
        if (mapping == null) {
            return emptyMap();
        }
        for (Map.Entry<String, Object> entry : mapping.entrySet()) {
            walk(entry.getKey(), entry.getValue(), types);
        }
        return types;
    }

    @SuppressWarnings("unchecked")
    private static void walk(String name, Object value, Map<String, EsField> out) {
        if ((value instanceof Map) == false) {
            throw new IllegalArgumentException("Unrecognized mapping for [" + name + "]: " + value);
        }
        Map<String, Object> content = (Map<String, Object>) value;

        if ("nested".equals(content.get("type"))) {
            // IndexResolver strips nested fields entirely; mirror that.
            return;
        }

        DataType dataType = resolveType(content);

        final Map<String, EsField> properties;
        if (dataType == OBJECT) {
            properties = fromProperties(content);
        } else if (content.containsKey("fields")) {
            Object fields = content.get("fields");
            properties = (fields instanceof Map) ? startWalking((Map<String, Object>) fields) : Collections.emptyMap();
        } else {
            properties = fromProperties(content);
        }

        boolean docValues = boolSetting(content.get("doc_values"), dataType.hasDocValues());
        boolean isDimension = boolSetting(content.get("time_series_dimension"), false);
        boolean isMetric = content.containsKey("time_series_metric");
        if (isDimension && isMetric) {
            throw new IllegalStateException("Field [" + name + "] is both dimension and metric");
        }
        EsField.TimeSeriesFieldType tsType = EsField.TimeSeriesFieldType.NONE;
        if (isDimension) {
            tsType = EsField.TimeSeriesFieldType.DIMENSION;
        }
        if (isMetric) {
            tsType = EsField.TimeSeriesFieldType.METRIC;
        }

        final EsField field;
        if (dataType == TEXT) {
            field = new TextEsField(name, properties, docValues, false, tsType);
        } else if (dataType == KEYWORD) {
            int length = intSetting(content.get("ignore_above"), Short.MAX_VALUE);
            boolean normalized = content.get("normalizer") != null
                && content.get("normalizer").toString().isBlank() == false;
            field = new KeywordEsField(name, properties, docValues, length, normalized, false, tsType);
        } else if (dataType == DATETIME) {
            field = DateEsField.dateEsField(name, properties, docValues, tsType);
        } else if (dataType == UNSUPPORTED) {
            String type = String.valueOf(content.get("type"));
            field = new UnsupportedEsField(name, List.of(type), null, properties);
            propagateUnsupported(name, type, properties);
        } else {
            field = new EsField(name, dataType, properties, docValues, tsType);
        }
        out.put(name, field);
    }

    private static DataType resolveType(Map<String, Object> content) {
        if (content.containsKey("type")) {
            String typeName = content.get("type").toString();
            if ("constant_keyword".equals(typeName) || "wildcard".equals(typeName)) {
                return KEYWORD;
            }
            // Text-family storage types that field_caps surfaces as plain "text" at
            // search time. Mirror that here so callers can pass raw index mappings
            // (e.g. ECS's `message: match_only_text`) without the analyzer marking
            // them UNSUPPORTED — which would then reject perfectly valid queries.
            if ("match_only_text".equals(typeName) || "annotated_text".equals(typeName)) {
                return TEXT;
            }
            Object metricsTypeParameter = content.get(TimeSeriesParams.TIME_SERIES_METRIC_PARAM);
            TimeSeriesParams.MetricType metricType = null;
            if (metricsTypeParameter instanceof String s) {
                metricType = TimeSeriesParams.MetricType.fromString(s);
            } else if (metricsTypeParameter != null) {
                metricType = (TimeSeriesParams.MetricType) metricsTypeParameter;
            }
            try {
                return EsqlDataTypeRegistry.INSTANCE.fromEs(typeName, metricType);
            } catch (IllegalArgumentException ignore) {
                return UNSUPPORTED;
            }
        }
        if (content.containsKey("properties")) {
            return OBJECT;
        }
        return UNSUPPORTED;
    }

    private static boolean boolSetting(Object value, boolean defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        String s = value.toString().toLowerCase();
        return switch (s) {
            case "true", "1", "yes", "on" -> true;
            case "false", "0", "no", "off" -> false;
            default -> defaultValue;
        };
    }

    private static int intSetting(Object value, int defaultValue) {
        return value == null ? defaultValue : Integer.parseInt(value.toString());
    }

    private static void propagateUnsupported(String inherited, String originalType, Map<String, EsField> properties) {
        if (properties == null || properties.isEmpty()) {
            return;
        }
        for (Map.Entry<String, EsField> entry : properties.entrySet()) {
            EsField field = entry.getValue();
            UnsupportedEsField u;
            if (field instanceof UnsupportedEsField unsupported) {
                u = new UnsupportedEsField(unsupported.getName(), List.of(originalType), inherited, unsupported.getProperties());
            } else {
                u = new UnsupportedEsField(field.getName(), List.of(originalType), inherited, field.getProperties());
            }
            entry.setValue(u);
            propagateUnsupported(inherited, originalType, u.getProperties());
        }
    }
}
