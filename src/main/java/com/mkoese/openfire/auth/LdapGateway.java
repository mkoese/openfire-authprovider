package com.mkoese.openfire.auth;

/**
 * Seam around the directory. Both methods are fail-closed: connectivity
 * problems are logged by implementations and reported as {@code null}/{@code false}.
 */
public interface LdapGateway {

    /**
     * User attributes read from the directory: {@code name} via {@code
     * ldap.nameField} (AD: displayName), {@code email} via {@code
     * ldap.emailField} (AD: mail). A field absent in AD is {@code null}.
     */
    record Profile(String name, String email) {
    }

    /**
     * Directory lookup: the user's profile, or {@code null} when the user is
     * absent or the directory is unreachable (fail closed — both reject).
     */
    Profile find(String username);

    /** Whether the directory accepts a bind as this user with this password. */
    boolean bind(String username, String password);
}
