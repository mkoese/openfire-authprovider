package com.mkoese.openfire.auth;

/**
 * Password policy for locally managed (DB) passwords. Openfire 5.0.x has no
 * built-in policy or validator SPI, so this is enforced in the provider's
 * {@code setPassword} — the choke point for admin console changes, XEP-0077
 * password changes, and programmatic updates.
 *
 * Violations throw {@link UnsupportedOperationException}: the only exception
 * an AuthProvider.setPassword may signal besides UserNotFoundException.
 *
 * Properties (system properties, all optional):
 *   adAuth.password.minLength      minimum length            (default 12)
 *   adAuth.password.minClasses     of lower/upper/digit/other (default 3)
 *   adAuth.password.rejectUsername reject if it contains the username (default true)
 */
final class PasswordPolicy {

    static final String PROP_MIN_LENGTH = "adAuth.password.minLength";
    static final String PROP_MIN_CLASSES = "adAuth.password.minClasses";
    static final String PROP_REJECT_USERNAME = "adAuth.password.rejectUsername";

    static final int DEFAULT_MIN_LENGTH = 12;
    static final int DEFAULT_MIN_CLASSES = 3;

    private final Settings settings;

    PasswordPolicy(Settings settings) {
        this.settings = settings;
    }

    /**
     * @throws UnsupportedOperationException if the password violates the policy
     */
    void validate(String username, String password) {
        if (password == null || password.isEmpty()) {
            throw new UnsupportedOperationException("Password policy violation: password must not be empty.");
        }

        final int minLength = settings.getInt(PROP_MIN_LENGTH, DEFAULT_MIN_LENGTH);
        if (password.length() < minLength) {
            throw new UnsupportedOperationException(
                "Password policy violation: minimum length is " + minLength + " characters.");
        }

        final int minClasses = settings.getInt(PROP_MIN_CLASSES, DEFAULT_MIN_CLASSES);
        if (characterClasses(password) < minClasses) {
            throw new UnsupportedOperationException(
                "Password policy violation: must contain at least " + minClasses
                    + " of: lowercase, uppercase, digits, other characters.");
        }

        if (settings.getBoolean(PROP_REJECT_USERNAME, true)
                && username != null && username.length() >= 3
                && password.toLowerCase().contains(username.toLowerCase())) {
            throw new UnsupportedOperationException(
                "Password policy violation: password must not contain the username.");
        }
    }

    /** Counts how many of the four classes (lower/upper/digit/other) appear in the password. */
    private static int characterClasses(String password) {
        boolean lower = false, upper = false, digit = false, other = false;
        for (final char c : password.toCharArray()) {
            if (Character.isLowerCase(c)) lower = true;
            else if (Character.isUpperCase(c)) upper = true;
            else if (Character.isDigit(c)) digit = true;
            else other = true;
        }
        return (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (other ? 1 : 0);
    }
}
