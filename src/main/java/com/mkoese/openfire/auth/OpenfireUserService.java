package com.mkoese.openfire.auth;

import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Production {@link UserService} backed by Openfire's {@link UserManager}. */
final class OpenfireUserService implements UserService {

    private static final Logger Log = LoggerFactory.getLogger(OpenfireUserService.class);

    @Override
    public boolean exists(String username) {
        try {
            UserManager.getInstance().getUser(username);
            return true;
        } catch (UserNotFoundException e) {
            return false;
        }
    }

    /** Creates the ofUser row with the AD profile (name/email = admin console Name/Email). */
    @Override
    public void create(String username, String password, String name, String email) throws Exception {
        // DefaultUserProvider.createUser inserts the ofUser row and then calls
        // AuthFactory.setPassword — which dispatches back into the registered
        // (our) provider. The caller guards this with the enrollment flag.
        UserManager.getInstance().createUser(username, password, name, email);
    }

    /** Writes changed AD name/email onto the ofUser row; never throws — profile is cosmetic. */
    @Override
    public void syncProfile(String username, String name, String email) {
        try {
            final User user = UserManager.getInstance().getUser(username);
            // Compare first: User setters write to the DB unconditionally.
            if (name != null && !name.equals(user.getName())) {
                user.setName(name);
                Log.debug("Updated name of '{}' from the directory", username);
            }
            if (email != null && !email.equals(user.getEmail())) {
                user.setEmail(email);
                Log.debug("Updated email of '{}' from the directory", username);
            }
        } catch (Exception e) {
            Log.warn("Profile sync failed for '{}': {}", username, e.getMessage());
            Log.debug("Profile sync stack trace", e);
        }
    }
}
