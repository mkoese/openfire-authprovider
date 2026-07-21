package com.mkoese.openfire.auth;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.auth.AuthorizationPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authorization policy for GSSAPI (Kerberos) logins, replacing
 * DefaultAuthorizationPolicy:
 *
 *   - authzid must equal the Kerberos principal's primary (no proxy auth)
 *   - the realm must be approved (sasl.approvedRealms / sasl.realm / XMPP domain)
 *   - the user must exist in Active Directory (same gate as PLAIN)
 *   - missing local accounts are JIT-created with a random 32-char password;
 *     PLAIN login is intentionally impossible until the user sets a real DB
 *     password (Kerberos SSO keeps working)
 *   - name/email are copied from AD at creation and refreshed on every SSO
 *     login (attributes per ldap.nameField / ldap.emailField)
 *
 * Registration:
 *   provider.authorization.classList = com.mkoese.openfire.auth.AdGatedAuthorizationPolicy
 */
public class AdGatedAuthorizationPolicy implements AuthorizationPolicy {

    private static final Logger Log = LoggerFactory.getLogger(AdGatedAuthorizationPolicy.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGIT = "0123456789";
    private static final String OTHER = "!#$%*+-=_";

    private final LdapGateway ldap;
    private final UserService users;
    private final Settings settings;
    private final Supplier<String> xmppDomain;

    /** Production wiring: Openfire's LdapManager, UserManager and properties. */
    public AdGatedAuthorizationPolicy() {
        this(new LdapManagerGateway(), new OpenfireUserService(), new JiveGlobalsSettings(),
            () -> XMPPServer.getInstance().getServerInfo().getXMPPDomain());
    }

    /** Test seam: every dependency injectable, no running Openfire needed. */
    AdGatedAuthorizationPolicy(LdapGateway ldap, UserService users, Settings settings,
                               Supplier<String> xmppDomain) {
        this.ldap = ldap;
        this.users = users;
        this.settings = settings;
        this.xmppDomain = xmppDomain;
    }

    /** GSSAPI entry point: realm approved + authzid equals the principal + user exists in AD; JIT-creates the local account (with AD name/email) or refreshes the profile. */
    @Override
    public boolean authorize(String username, String principal) {
        if (username == null || principal == null) {
            return false;
        }

        String primary = principal;
        String realm = "";
        final int idx = principal.indexOf('@');
        if (idx > -1) {
            primary = principal.substring(0, idx);
            realm = principal.substring(idx + 1);
        }

        if (!realmApproved(realm)) {
            Log.debug("Rejecting principal '{}': realm '{}' not approved", principal, realm);
            return false;
        }
        if (!username.equalsIgnoreCase(primary)) {
            Log.debug("Rejecting authzid '{}' for principal '{}': no proxy auth", username, principal);
            return false;
        }

        final String user = username.trim().toLowerCase();
        final LdapGateway.Profile ad = ldap.find(user);
        if (ad == null) {
            Log.debug("Rejecting '{}': not present in the directory", user);
            return false;
        }

        if (!users.exists(user)) {
            try {
                AdGatedAuthProvider.runEnrolling(() -> {
                    try {
                        users.create(user, randomPassword(), ad.name(), ad.email());
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                });
                Log.info("JIT-created local account '{}' for Kerberos principal '{}'", user, principal);
            } catch (RuntimeException e) {
                Log.error("Failed to JIT-create local account '{}'", user, e);
                return false;
            }
        } else {
            users.syncProfile(user, ad.name(), ad.email());
        }
        Log.debug("Authorized Kerberos principal '{}' as '{}'", principal, user);
        return true;
    }

    /** Realm is empty/our XMPP domain, equals sasl.realm, or listed in sasl.approvedRealms. */
    private boolean realmApproved(String realm) {
        if (realm.isEmpty() || realm.equalsIgnoreCase(xmppDomain.get())) {
            return true;
        }
        if (realm.equalsIgnoreCase(settings.get("sasl.realm", ""))) {
            return true;
        }
        return settings.getLowerCaseList("sasl.approvedRealms", "").contains(realm.toLowerCase());
    }

    /**
     * Random 32-char password containing all four character classes, so it
     * always satisfies {@link PasswordPolicy} regardless of configuration.
     */
    static String randomPassword() {
        final List<Character> chars = new ArrayList<>(32);
        for (final String clazz : new String[] {LOWER, UPPER, DIGIT, OTHER}) {
            for (int i = 0; i < 8; i++) {
                chars.add(clazz.charAt(RANDOM.nextInt(clazz.length())));
            }
        }
        Collections.shuffle(chars, RANDOM);
        final StringBuilder sb = new StringBuilder(chars.size());
        chars.forEach(sb::append);
        return sb.toString();
    }

    @Override
    public String name() {
        return "AD-gated authorization policy";
    }

    @Override
    public String description() {
        return "Authorizes Kerberos principals whose realm is approved and whose user exists in "
            + "Active Directory; JIT-creates missing local accounts with a random password.";
    }
}
