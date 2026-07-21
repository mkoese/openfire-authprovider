package com.mkoese.openfire.auth;

import javax.naming.ldap.Rdn;

import org.jivesoftware.openfire.ldap.LdapManager;
import org.jivesoftware.openfire.ldap.LdapUserProvider;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Production {@link LdapGateway} backed by Openfire's {@link LdapManager},
 * configured through the standard {@code ldap.*} system properties
 * (host, port, baseDN, adminDN, adminPassword, usernameField, ...).
 *
 * Works independently of which AuthProvider is registered — the same
 * mechanism LdapAuthProvider uses internally.
 */
final class LdapManagerGateway implements LdapGateway {

    private static final Logger Log = LoggerFactory.getLogger(LdapManagerGateway.class);

    /**
     * Lookup via the stock {@link LdapUserProvider}, so attributes are matched
     * exactly like Openfire's own LDAP integration: {@code ldap.nameField}
     * (templates like "{givenName} {sn}" supported) → name, {@code
     * ldap.emailField} → email. Constructed per call: it is a cheap
     * property-read and always reflects the current configuration.
     */
    @Override
    public Profile find(String username) {
        try {
            final User user = new LdapUserProvider().loadUser(username);
            return new Profile(blankToNull(user.getName()), blankToNull(user.getEmail()));
        } catch (UserNotFoundException e) {
            // LdapUserProvider wraps BOTH "no such user" and connectivity
            // errors in UserNotFoundException -- fail closed either way.
            Log.debug("LDAP lookup for '{}' found no user: {}", username, e.getMessage());
            return null;
        } catch (Exception e) {
            Log.warn("LDAP lookup failed for '{}': {}", username, e.getMessage());
            Log.debug("LDAP lookup stack trace", e);
            return null;
        }
    }

    @Override
    public boolean bind(String username, String password) {
        // Never attempt a bind with an empty password: AD would treat it as an
        // unauthenticated bind and return success (RFC 4513 §5.1.2).
        if (username == null || password == null || password.isEmpty()) {
            return false;
        }
        try {
            final LdapManager manager = LdapManager.getInstance();
            final Rdn[] userRDN = manager.findUserRDN(username);
            return manager.checkAuthentication(userRDN, password);
        } catch (Exception e) {
            Log.warn("LDAP bind check failed for '{}': {}", username, e.getMessage());
            Log.debug("LDAP bind check stack trace", e);
            return false;
        }
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value;
    }
}
