package com.mkoese.openfire.auth;

import java.util.Arrays;
import java.util.List;

/**
 * Thin property-lookup seam so provider logic is unit-testable without a
 * running Openfire (JiveGlobals requires a live database connection).
 */
@FunctionalInterface
public interface Settings {

    /** Raw property value, or {@code null} if unset. */
    String get(String key);

    /** Property value, or the default when unset or blank. */
    default String get(String key, String defaultValue) {
        final String value = get(key);
        return (value == null || value.isBlank()) ? defaultValue : value.trim();
    }

    /** Boolean property ("true"/"false"), or the default when unset or blank. */
    default boolean getBoolean(String key, boolean defaultValue) {
        final String value = get(key);
        return (value == null || value.isBlank()) ? defaultValue : Boolean.parseBoolean(value.trim());
    }

    /** Integer property, or the default when unset, blank or not a number. */
    default int getInt(String key, int defaultValue) {
        final String value = get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /** Comma-separated list property, trimmed and lower-cased. */
    default List<String> getLowerCaseList(String key, String defaultValue) {
        return Arrays.stream(get(key, defaultValue).split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .map(String::toLowerCase)
            .toList();
    }
}
