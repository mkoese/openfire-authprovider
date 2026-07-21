package com.mkoese.openfire.auth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.jivesoftware.openfire.auth.AuthProvider;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AdGatedAuthProviderTest {

    private static final String DOMAIN = "chat.example.com";
    private static final String STRONG = "Str0ng-Passw0rd!";
    private static final LdapGateway.Profile AD_PROFILE =
        new LdapGateway.Profile("Alice Example", "alice@example.com");

    @Mock private AuthProvider delegate;
    @Mock private LdapGateway ldap;
    @Mock private UserService users;

    private final Map<String, String> props = new HashMap<>();
    private AdGatedAuthProvider provider;

    @BeforeEach
    void setUp() {
        provider = new AdGatedAuthProvider(delegate, ldap, users, props::get, () -> DOMAIN);
    }

    // --- LDAP gate ---------------------------------------------------------

    @Test
    void rejectsWhenUserNotInLdap() {
        when(ldap.find("alice")).thenReturn(null);

        assertThrows(UnauthorizedException.class, () -> provider.authenticate("alice", STRONG));
        verifyNoInteractions(delegate, users);
    }

    @Test
    void localOnlyUserBypassesLdap() throws Exception {
        provider.authenticate("admin", STRONG);

        verify(delegate).authenticate("admin", STRONG);
        verifyNoInteractions(ldap, users);
    }

    @Test
    void customLocalOnlyListIsHonored() throws Exception {
        props.put(AdGatedAuthProvider.PROP_LOCAL_ONLY_USERS, "admin, breakglass");

        provider.authenticate("breakglass", STRONG);

        verify(delegate).authenticate("breakglass", STRONG);
        verifyNoInteractions(ldap);
    }

    // --- Enrollment (first login) ------------------------------------------

    @Test
    void enrollsOnFirstLoginWhenAdBindSucceeds() throws Exception {
        when(ldap.find("alice")).thenReturn(AD_PROFILE);
        when(users.exists("alice")).thenReturn(false);
        when(ldap.bind("alice", STRONG)).thenReturn(true);

        provider.authenticate("alice", STRONG);

        // AD name/email are stored on the JIT-created account
        verify(users).create("alice", STRONG, "Alice Example", "alice@example.com");
        verify(delegate, never()).authenticate(anyString(), anyString());
    }

    @Test
    void enrollsEvenWhenAdAttributesAreMissing() throws Exception {
        when(ldap.find("bob")).thenReturn(new LdapGateway.Profile(null, null));
        when(users.exists("bob")).thenReturn(false);
        when(ldap.bind("bob", STRONG)).thenReturn(true);

        provider.authenticate("bob", STRONG);

        verify(users).create("bob", STRONG, null, null);
    }

    @Test
    void rejectsEnrollmentWhenAdBindFails() throws Exception {
        when(ldap.find("alice")).thenReturn(AD_PROFILE);
        when(users.exists("alice")).thenReturn(false);
        when(ldap.bind("alice", "wrong")).thenReturn(false);

        assertThrows(UnauthorizedException.class, () -> provider.authenticate("alice", "wrong"));
        verify(users, never()).create(anyString(), anyString(), any(), any());
    }

    @Test
    void enrollmentBypassesPasswordPolicy() throws Exception {
        // AD passwords are not subject to the local policy. Simulate Openfire's
        // re-entrancy: users.create -> AuthFactory.setPassword -> our setPassword.
        final String weakAdPassword = "weak";
        when(ldap.find("alice")).thenReturn(AD_PROFILE);
        when(users.exists("alice")).thenReturn(false);
        when(ldap.bind("alice", weakAdPassword)).thenReturn(true);
        doAnswer(inv -> {
            provider.setPassword(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(users).create(anyString(), anyString(), any(), any());

        assertDoesNotThrow(() -> provider.authenticate("alice", weakAdPassword));
        verify(delegate).setPassword("alice", weakAdPassword);
    }

    // --- Existing accounts (DB hash is authoritative) -----------------------

    @Test
    void delegatesToLocalHashWhenAccountExists() throws Exception {
        when(ldap.find("alice")).thenReturn(AD_PROFILE);
        when(users.exists("alice")).thenReturn(true);

        provider.authenticate("alice", STRONG);

        verify(delegate).authenticate("alice", STRONG);
        verify(users, never()).create(anyString(), anyString(), any(), any());
        // successful login refreshes name/email from AD
        verify(users).syncProfile("alice", "Alice Example", "alice@example.com");
    }

    @Test
    void rejectsOnLocalHashMismatch() throws Exception {
        when(ldap.find("alice")).thenReturn(AD_PROFILE);
        when(users.exists("alice")).thenReturn(true);
        doThrow(new UnauthorizedException()).when(delegate).authenticate("alice", "wrong");

        assertThrows(UnauthorizedException.class, () -> provider.authenticate("alice", "wrong"));
        // reenroll disabled by default: AD bind is never consulted
        verify(ldap, never()).bind(anyString(), anyString());
        // no profile writes for a failed login
        verify(users, never()).syncProfile(anyString(), any(), any());
    }

    @Test
    void reenrollsOnBindSuccessWhenEnabled() throws Exception {
        props.put(AdGatedAuthProvider.PROP_REENROLL, "true");
        when(ldap.find("alice")).thenReturn(AD_PROFILE);
        when(users.exists("alice")).thenReturn(true);
        doThrow(new UnauthorizedException()).when(delegate).authenticate("alice", STRONG);
        when(ldap.bind("alice", STRONG)).thenReturn(true);

        assertDoesNotThrow(() -> provider.authenticate("alice", STRONG));
        verify(delegate).setPassword("alice", STRONG);
    }

    // --- Username normalization ---------------------------------------------

    @Test
    void stripsOwnDomainAndLowercases() throws Exception {
        when(ldap.find("alice")).thenReturn(AD_PROFILE);
        when(users.exists("alice")).thenReturn(true);

        provider.authenticate("Alice@" + DOMAIN, STRONG);

        verify(delegate).authenticate("alice", STRONG);
    }

    @Test
    void rejectsForeignDomain() {
        assertThrows(UnauthorizedException.class,
            () -> provider.authenticate("alice@evil.example.org", STRONG));
        verifyNoInteractions(ldap, delegate, users);
    }

    @Test
    void rejectsNullCredentials() {
        assertThrows(UnauthorizedException.class, () -> provider.authenticate(null, STRONG));
        assertThrows(UnauthorizedException.class, () -> provider.authenticate("alice", null));
    }

    @Test
    void rejectsEmptyPasswordBeforeAnyLdapBind() {
        // Regression: an empty password must never reach the directory. AD would
        // accept a simple bind with an empty password as an unauthenticated bind
        // and the user would be enrolled/authenticated. Reject before any lookup.
        assertThrows(UnauthorizedException.class, () -> provider.authenticate("alice", ""));
        verifyNoInteractions(ldap, delegate, users);
    }

    @Test
    void rejectsBlankUsername() {
        assertThrows(UnauthorizedException.class, () -> provider.authenticate("   ", STRONG));
        verifyNoInteractions(ldap, delegate, users);
    }

    // --- setPassword & policy ------------------------------------------------

    @Test
    void setPasswordEnforcesPolicy() throws Exception {
        assertThrows(UnsupportedOperationException.class,
            () -> provider.setPassword("alice", "short"));
        verify(delegate, never()).setPassword(anyString(), anyString());
    }

    @Test
    void setPasswordDelegatesWhenPolicyPasses() throws Exception {
        provider.setPassword("alice", STRONG);
        verify(delegate).setPassword("alice", STRONG);
    }

    // --- SCRAM delegation -----------------------------------------------------

    @Test
    void scramGettersDelegate() throws Exception {
        when(delegate.getSalt("alice")).thenReturn("salt");
        when(delegate.getIterations("alice")).thenReturn(4096);
        when(delegate.getServerKey("alice")).thenReturn("sk");
        when(delegate.getStoredKey("alice")).thenReturn("stk");
        when(delegate.isScramSupported()).thenReturn(true);

        org.junit.jupiter.api.Assertions.assertEquals("salt", provider.getSalt("alice"));
        org.junit.jupiter.api.Assertions.assertEquals(4096, provider.getIterations("alice"));
        org.junit.jupiter.api.Assertions.assertEquals("sk", provider.getServerKey("alice"));
        org.junit.jupiter.api.Assertions.assertEquals("stk", provider.getStoredKey("alice"));
        org.junit.jupiter.api.Assertions.assertTrue(provider.isScramSupported());
        // SCRAM getters must NOT consult LDAP (enrolled users only)
        verifyNoInteractions(ldap);
    }
}
