package com.mkoese.openfire.auth;

import java.util.function.Supplier;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.auth.AuthProvider;
import org.jivesoftware.openfire.auth.ConnectionException;
import org.jivesoftware.openfire.auth.DefaultAuthProvider;
import org.jivesoftware.openfire.auth.InternalUnauthenticatedException;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

/**
 * AD-gated AuthProvider with local (DB) password hashes.
 *
 * PLAIN / admin console flow:
 *   1. Local-only users (default: admin) → straight to DefaultAuthProvider, no LDAP.
 *   2. User must exist in Active Directory, else reject.
 *   3. No local account yet → enrollment: password verified via AD bind; on
 *      success the account is JIT-created and the password hash stored locally.
 *   4. Local account exists → verify against the stored hash (SCRAM columns in
 *      ofUser) via DefaultAuthProvider. The DB password is authoritative and
 *      may diverge from AD after a password change.
 *
 * SCRAM-SHA-1 works untouched: the SCRAM getters delegate to
 * DefaultAuthProvider, which serves salt/storedKey/serverKey/iterations from
 * ofUser. (Deliberately no HybridAuthProvider: its SCRAM getters are broken in
 * 5.x — they compute but never return, then throw UserNotFoundException.)
 *
 * Registration (JAR must live in OPENFIRE_HOME/lib, not a plugin):
 *   provider.auth.className = com.mkoese.openfire.auth.AdGatedAuthProvider
 *
 * Properties:
 *   adAuth.localOnlyUsers         comma list bypassing the AD gate (default "admin")
 *   adAuth.reenrollOnBindSuccess  on local hash mismatch, retry AD bind and
 *                                 re-sync the local hash (default false — the
 *                                 DB password stays authoritative)
 *   adAuth.password.*             see {@link PasswordPolicy}
 *   ldap.*                        standard Openfire LDAP settings (LdapManager)
 *   ldap.nameField / ldap.emailField  AD attributes copied onto the Openfire
 *                                 user (Name/Email) at enrollment and refreshed
 *                                 on every PLAIN login (defaults: cn / mail)
 */
public class AdGatedAuthProvider implements AuthProvider {

    static final String PROP_LOCAL_ONLY_USERS = "adAuth.localOnlyUsers";
    static final String PROP_REENROLL = "adAuth.reenrollOnBindSuccess";

    private static final Logger Log = LoggerFactory.getLogger(AdGatedAuthProvider.class);

    /**
     * Guards re-entrancy: UserManager.createUser → DefaultUserProvider →
     * AuthFactory.setPassword → our setPassword. While enrolling, the password
     * policy is skipped (the password was verified against AD, not chosen
     * locally) and no LDAP gate applies.
     */
    private static final ThreadLocal<Boolean> ENROLLING = ThreadLocal.withInitial(() -> Boolean.FALSE);

    private final AuthProvider delegate;
    private final LdapGateway ldap;
    private final UserService users;
    private final Settings settings;
    private final Supplier<String> xmppDomain;
    private final PasswordPolicy policy;

    /** Production wiring: Openfire's own DB store, LdapManager, UserManager and properties. */
    public AdGatedAuthProvider() {
        this(new DefaultAuthProvider(), new LdapManagerGateway(), new OpenfireUserService(),
            new JiveGlobalsSettings(),
            () -> XMPPServer.getInstance().getServerInfo().getXMPPDomain());
    }

    /** Test seam: every dependency injectable, no running Openfire needed. */
    AdGatedAuthProvider(AuthProvider delegate, LdapGateway ldap, UserService users,
                        Settings settings, Supplier<String> xmppDomain) {
        this.delegate = delegate;
        this.ldap = ldap;
        this.users = users;
        this.settings = settings;
        this.xmppDomain = xmppDomain;
        this.policy = new PasswordPolicy(settings);
    }

    /** PLAIN/console entry point: local-only bypass → AD gate (lookup incl. name/email) → enroll (first login) or verify stored hash + refresh profile. */
    @Override
    public void authenticate(String username, String password)
            throws UnauthorizedException, ConnectionException, InternalUnauthenticatedException {
        if (username == null || password == null) {
            Log.debug("Rejecting authentication: null username or password");
            throw new UnauthorizedException();
        }
        // Reject empty credentials BEFORE any LDAP bind. A simple bind to Active
        // Directory with a valid DN and a zero-length password is treated as an
        // "unauthenticated bind" and returns success (RFC 4513 §5.1.2) -- without
        // this guard an attacker could enroll/authenticate as any un-enrolled AD
        // user by sending a blank password. Defense in depth: LdapManagerGateway
        // also refuses to bind with an empty password.
        if (username.isBlank() || password.isEmpty()) {
            Log.debug("Rejecting '{}': empty username or password", username);
            throw new UnauthorizedException("Empty username or password.");
        }
        username = normalize(username);
        // NOTE: log usernames, decisions and outcomes only -- NEVER the password
        // or any credential material. See getLogSafe usage across this class.
        Log.trace("authenticate: evaluating '{}'", username);

        if (isLocalOnly(username)) {
            Log.debug("'{}' is a local-only user; authenticating against the local store (AD gate bypassed)", username);
            delegate.authenticate(username, password);
            Log.debug("'{}' authenticated (local-only)", username);
            return;
        }

        final LdapGateway.Profile ad = ldap.find(username);
        if (ad == null) {
            Log.debug("Rejecting '{}': not present in the directory", username);
            throw new UnauthorizedException("User not present in the directory.");
        }

        if (!users.exists(username)) {
            Log.debug("'{}' exists in AD but has no local account; enrolling", username);
            enroll(username, password, ad);
            return;
        }

        try {
            delegate.authenticate(username, password);
            Log.debug("'{}' authenticated against the local credential store", username);
            users.syncProfile(username, ad.name(), ad.email());
        } catch (UnauthorizedException e) {
            Log.debug("'{}' failed local authentication (stored-hash mismatch)", username);
            if (settings.getBoolean(PROP_REENROLL, false) && ldap.bind(username, password)) {
                Log.info("Re-enrolling '{}': local hash mismatch but AD bind succeeded", username);
                setPasswordEnrolling(username, password);
                users.syncProfile(username, ad.name(), ad.email());
                return;
            }
            throw e;
        }
    }

    /** First login: the offered password is verified against AD via bind, then stored locally with the AD profile. */
    private void enroll(String username, String password, LdapGateway.Profile profile) throws UnauthorizedException {
        if (!ldap.bind(username, password)) {
            Log.debug("Rejecting enrollment of '{}': AD bind failed", username);
            throw new UnauthorizedException("Directory did not accept the credentials.");
        }
        ENROLLING.set(Boolean.TRUE);
        try {
            users.create(username, password, profile.name(), profile.email());
        } catch (Exception e) {
            throw new UnauthorizedException("Failed to create local account for '" + username + "'", e);
        } finally {
            ENROLLING.remove();
        }
        Log.info("Enrolled new local account '{}' after AD bind verification", username);
    }

    /** Overwrite the stored hash with an AD-verified password (policy skipped — not locally chosen). */
    private void setPasswordEnrolling(String username, String password) throws UnauthorizedException {
        ENROLLING.set(Boolean.TRUE);
        try {
            delegate.setPassword(username, password);
        } catch (UserNotFoundException e) {
            throw new UnauthorizedException(e);
        } finally {
            ENROLLING.remove();
        }
    }

    /** Used by {@link AdGatedAuthorizationPolicy} for GSSAPI JIT provisioning. */
    static void runEnrolling(Runnable action) {
        ENROLLING.set(Boolean.TRUE);
        try {
            action.run();
        } finally {
            ENROLLING.remove();
        }
    }

    /** Choke point for ALL password changes (console, XEP-0077, code): enforces the policy, then stores locally. */
    @Override
    public void setPassword(String username, String password) throws UserNotFoundException {
        if (!ENROLLING.get()) {
            Log.trace("setPassword: validating policy for '{}'", username);
            try {
                policy.validate(bareUsername(username), password);
            } catch (UnsupportedOperationException e) {
                // The message states the unmet requirement, not the password.
                Log.debug("Password policy rejected a new password for '{}': {}", username, e.getMessage());
                throw e;
            }
        } else {
            Log.trace("setPassword: enrollment write for '{}' (policy skipped, AD-verified)", username);
        }
        delegate.setPassword(username, password);
        Log.debug("Password updated for '{}'", username);
    }

    /** Delegates to the local store (disabled anyway with user.scramHashedPasswordOnly=true). */
    @Override
    public String getPassword(String username) throws UserNotFoundException {
        return delegate.getPassword(username);
    }

    /** Delegates to the local store. */
    @Override
    public boolean supportsPasswordRetrieval() {
        return delegate.supportsPasswordRetrieval();
    }

    /** Always true via DefaultAuthProvider — this is what makes SCRAM-SHA-1 work. */
    @Override
    public boolean isScramSupported() {
        return delegate.isScramSupported();
    }

    @Override
    public String getSalt(String username) throws UserNotFoundException {
        // SCRAM entry point (client sent SCRAM-SHA-1). No LDAP gate: SCRAM only
        // works for already-enrolled users. Never logs salt/keys.
        Log.trace("SCRAM: serving credentials for '{}'", username);
        return delegate.getSalt(username);
    }

    /** SCRAM: iteration count from the stored hash in ofUser. */
    @Override
    public int getIterations(String username) throws UserNotFoundException {
        return delegate.getIterations(username);
    }

    /** SCRAM: server key from the stored hash in ofUser. */
    @Override
    public String getServerKey(String username) throws UserNotFoundException {
        return delegate.getServerKey(username);
    }

    /** SCRAM: stored key from the stored hash in ofUser. */
    @Override
    public String getStoredKey(String username) throws UserNotFoundException {
        return delegate.getStoredKey(username);
    }

    /** Unescape, lower-case and strip our own XMPP domain; reject foreign domains. */
    private String normalize(String username) throws UnauthorizedException {
        username = JID.unescapeNode(username.trim().toLowerCase());
        final int idx = username.indexOf('@');
        if (idx > -1) {
            final String domain = username.substring(idx + 1);
            if (!domain.equalsIgnoreCase(xmppDomain.get())) {
                throw new UnauthorizedException("Unknown domain: " + domain);
            }
            username = username.substring(0, idx);
        }
        return username;
    }

    /** Lenient variant for policy checks only (no rejection). */
    private static String bareUsername(String username) {
        if (username == null) {
            return null;
        }
        final int idx = username.indexOf('@');
        return (idx > -1 ? username.substring(0, idx) : username).trim().toLowerCase();
    }

    private boolean isLocalOnly(String username) {
        return settings.getLowerCaseList(PROP_LOCAL_ONLY_USERS, "admin").contains(username);
    }
}
