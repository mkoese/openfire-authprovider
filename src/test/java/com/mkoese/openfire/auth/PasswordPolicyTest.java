package com.mkoese.openfire.auth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

class PasswordPolicyTest {

    private final Map<String, String> props = new HashMap<>();
    private final PasswordPolicy policy = new PasswordPolicy(props::get);

    @Test
    void acceptsStrongPassword() {
        assertDoesNotThrow(() -> policy.validate("alice", "Str0ng-Passw0rd!"));
    }

    @Test
    void rejectsEmptyAndNull() {
        assertThrows(UnsupportedOperationException.class, () -> policy.validate("alice", ""));
        assertThrows(UnsupportedOperationException.class, () -> policy.validate("alice", null));
    }

    @Test
    void rejectsTooShort() {
        // 3 classes but only 11 chars
        assertThrows(UnsupportedOperationException.class, () -> policy.validate("alice", "Ab1-Ab1-Ab1"));
    }

    @Test
    void rejectsTooFewCharacterClasses() {
        // 16 chars but only lowercase + digits = 2 classes
        assertThrows(UnsupportedOperationException.class, () -> policy.validate("alice", "abcdefgh12345678"));
    }

    @Test
    void acceptsThreeOfFourClasses() {
        // lower + upper + digit, no symbol
        assertDoesNotThrow(() -> policy.validate("alice", "Abcdefgh12345678"));
    }

    @Test
    void rejectsPasswordContainingUsername() {
        assertThrows(UnsupportedOperationException.class, () -> policy.validate("alice", "Sup3r-alice-01!"));
    }

    @Test
    void usernameCheckCanBeDisabled() {
        props.put(PasswordPolicy.PROP_REJECT_USERNAME, "false");
        assertDoesNotThrow(() -> policy.validate("alice", "Sup3r-alice-01!"));
    }

    @Test
    void customMinLengthIsHonored() {
        props.put(PasswordPolicy.PROP_MIN_LENGTH, "20");
        assertThrows(UnsupportedOperationException.class, () -> policy.validate("alice", "Str0ng-Passw0rd!"));
        assertDoesNotThrow(() -> policy.validate("alice", "Str0ng-Passw0rd!Str0ng"));
    }

    @Test
    void customMinClassesIsHonored() {
        props.put(PasswordPolicy.PROP_MIN_CLASSES, "4");
        assertThrows(UnsupportedOperationException.class, () -> policy.validate("alice", "Abcdefgh12345678"));
        assertDoesNotThrow(() -> policy.validate("alice", "Abcdefgh1234567!"));
    }
}
