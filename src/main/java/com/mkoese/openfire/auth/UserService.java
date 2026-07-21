package com.mkoese.openfire.auth;

/** Seam around Openfire's user store for existence checks, JIT creation and profile sync. */
public interface UserService {

    /** Whether a local account (ofUser row) exists. */
    boolean exists(String username);

    /**
     * Create a local account with the given password and AD profile (name/email
     * may be {@code null}). Implementations re-enter the registered
     * AuthProvider's {@code setPassword} (Openfire behavior), so callers must
     * hold the enrollment flag.
     */
    void create(String username, String password, String name, String email) throws Exception;

    /**
     * Copy changed AD name/email onto the local account. Best-effort and
     * fail-open: {@code null} fields are skipped, errors only logged — profile
     * data must never break a login.
     */
    void syncProfile(String username, String name, String email);
}
