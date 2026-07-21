package com.mkoese.openfire.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AdGatedAuthorizationPolicyTest {

    private static final String DOMAIN = "chat.example.com";
    private static final LdapGateway.Profile AD_PROFILE =
        new LdapGateway.Profile("Alice Example", "alice@example.com");

    @Mock private LdapGateway ldap;
    @Mock private UserService users;

    private final Map<String, String> props = new HashMap<>();
    private AdGatedAuthorizationPolicy policy;

    @BeforeEach
    void setUp() {
        props.put("sasl.approvedRealms", "EXAMPLE.COM");
        policy = new AdGatedAuthorizationPolicy(ldap, users, props::get, () -> DOMAIN);
    }

    @Test
    void authorizesExistingUserFromApprovedRealm() {
        when(ldap.find("alice")).thenReturn(AD_PROFILE);
        when(users.exists("alice")).thenReturn(true);

        assertTrue(policy.authorize("alice", "alice@EXAMPLE.COM"));
    }

    @Test
    void realmMatchingXmppDomainIsApproved() {
        when(ldap.find("alice")).thenReturn(AD_PROFILE);
        when(users.exists("alice")).thenReturn(true);

        assertTrue(policy.authorize("alice", "alice@CHAT.EXAMPLE.COM"));
    }

    @Test
    void rejectsUnapprovedRealm() {
        assertFalse(policy.authorize("alice", "alice@EVIL.ORG"));
    }

    @Test
    void rejectsProxyAuthorization() {
        assertFalse(policy.authorize("bob", "alice@EXAMPLE.COM"));
    }

    @Test
    void rejectsWhenNotInDirectory() {
        when(ldap.find("alice")).thenReturn(null);

        assertFalse(policy.authorize("alice", "alice@EXAMPLE.COM"));
    }

    @Test
    void jitCreatesMissingLocalAccount() throws Exception {
        when(ldap.find("alice")).thenReturn(AD_PROFILE);
        when(users.exists("alice")).thenReturn(false);

        assertTrue(policy.authorize("alice", "alice@EXAMPLE.COM"));

        final ArgumentCaptor<String> password = ArgumentCaptor.forClass(String.class);
        // AD name/email land on the JIT-created account
        verify(users).create(eq("alice"), password.capture(), eq("Alice Example"), eq("alice@example.com"));
        assertEquals(32, password.getValue().length());
    }

    @Test
    void doesNotCreateWhenAccountExists() throws Exception {
        when(ldap.find("alice")).thenReturn(AD_PROFILE);
        when(users.exists("alice")).thenReturn(true);

        assertTrue(policy.authorize("alice", "alice@EXAMPLE.COM"));
        verify(users, never()).create(anyString(), anyString(), any(), any());
        // existing accounts get their name/email refreshed on every SSO login
        verify(users).syncProfile("alice", "Alice Example", "alice@example.com");
    }

    @Test
    void randomPasswordAlwaysSatisfiesStrictestPolicy() {
        final Map<String, String> strict = new HashMap<>();
        strict.put(PasswordPolicy.PROP_MIN_CLASSES, "4");
        strict.put(PasswordPolicy.PROP_MIN_LENGTH, "32");
        final PasswordPolicy strictPolicy = new PasswordPolicy(strict::get);

        for (int i = 0; i < 100; i++) {
            final String pw = AdGatedAuthorizationPolicy.randomPassword();
            org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> strictPolicy.validate("alice", pw));
        }
    }

    @Test
    void rejectsNullInputs() {
        assertFalse(policy.authorize(null, "alice@EXAMPLE.COM"));
        assertFalse(policy.authorize("alice", null));
    }
}
