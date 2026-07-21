package com.mkoese.openfire.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.jivesoftware.openfire.auth.AuthProvider;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

/**
 * Safety net for the "never log credentials" invariant: drives every auth flow
 * at TRACE level with a distinctive password and asserts the password never
 * appears in any captured log line (message, arguments, or throwable chain).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class LoggingSafetyTest {

    private static final String DOMAIN = "chat.example.com";
    /** Distinctive, policy-compliant secret that must never reach a log line. */
    private static final String SECRET = "Zx9!Qwerty-SECRET-do-not-log-42";

    @Mock private AuthProvider delegate;
    @Mock private LdapGateway ldap;
    @Mock private UserService users;

    private final Map<String, String> props = new HashMap<>();
    private AdGatedAuthProvider provider;

    private Logger authLogger;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setUp() {
        provider = new AdGatedAuthProvider(delegate, ldap, users, props::get, () -> DOMAIN);

        authLogger = (Logger) LoggerFactory.getLogger("com.mkoese.openfire.auth");
        authLogger.setLevel(Level.TRACE);       // capture everything, incl. trace
        appender = new ListAppender<>();
        appender.start();
        authLogger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        authLogger.detachAppender(appender);
    }

    @Test
    void noFlowLeaksThePasswordIntoLogs() throws Exception {
        // 1. local-only admin
        provider.authenticate("admin", SECRET);

        // 2. enrollment (AD bind ok → create → re-entrant setPassword)
        final LdapGateway.Profile profile = new LdapGateway.Profile("Some Name", "user@example.com");
        when(ldap.find("alice")).thenReturn(profile);
        when(users.exists("alice")).thenReturn(false);
        when(ldap.bind("alice", SECRET)).thenReturn(true);
        doAnswer(inv -> {
            provider.setPassword(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(users).create(anyString(), anyString(), any(), any());
        provider.authenticate("alice", SECRET);

        // 3. existing account, success (incl. profile sync)
        when(ldap.find("bob")).thenReturn(profile);
        when(users.exists("bob")).thenReturn(true);
        provider.authenticate("bob", SECRET);

        // 4. existing account, local hash mismatch
        when(ldap.find("carol")).thenReturn(profile);
        when(users.exists("carol")).thenReturn(true);
        doThrow(new UnauthorizedException()).when(delegate).authenticate("carol", SECRET);
        assertThrows(UnauthorizedException.class, () -> provider.authenticate("carol", SECRET));

        // 5. password change accepted
        provider.setPassword("dave", SECRET);

        // 6. password change rejected by policy (weak password)
        assertThrows(UnsupportedOperationException.class, () -> provider.setPassword("erin", "weak"));

        // 7. SCRAM getters
        lenient().when(delegate.getSalt("frank")).thenReturn("c2FsdA==");
        provider.getSalt("frank");

        assertNoCapturedLineContains(SECRET);
        // "weak" is also a password — must not be logged either
        assertNoCapturedLineContains("weak");
    }

    private void assertNoCapturedLineContains(String secret) {
        for (final ILoggingEvent e : appender.list) {
            assertFalse(e.getFormattedMessage().contains(secret),
                "Password leaked in log message: " + e.getFormattedMessage());
            if (e.getArgumentArray() != null) {
                for (final Object arg : e.getArgumentArray()) {
                    assertFalse(String.valueOf(arg).contains(secret),
                        "Password leaked in a log argument of: " + e.getFormattedMessage());
                }
            }
            var t = e.getThrowableProxy();
            while (t != null) {
                assertFalse(String.valueOf(t.getMessage()).contains(secret),
                    "Password leaked in a logged exception: " + t.getMessage());
                t = t.getCause();
            }
        }
    }
}
