package com.mkoese.openfire.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

/**
 * Guards that require no running Openfire: the empty-password short-circuit in
 * {@link LdapManagerGateway#bind} returns before ever calling {@code
 * LdapManager.getInstance()}, so it is unit-testable in isolation. This closes
 * the AD unauthenticated-bind bypass (RFC 4513 §5.1.2) at the gateway layer.
 */
class LdapManagerGatewayTest {

    private final LdapManagerGateway gateway = new LdapManagerGateway();

    @Test
    void bindRefusesEmptyPassword() {
        assertFalse(gateway.bind("alice", ""));
    }

    @Test
    void bindRefusesNullPassword() {
        assertFalse(gateway.bind("alice", null));
    }

    @Test
    void bindRefusesNullUsername() {
        assertFalse(gateway.bind(null, "whatever"));
    }
}
