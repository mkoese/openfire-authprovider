package com.mkoese.openfire.auth;

import org.jivesoftware.util.JiveGlobals;

/** Production {@link Settings} backed by Openfire system properties. */
final class JiveGlobalsSettings implements Settings {

    @Override
    public String get(String key) {
        return JiveGlobals.getProperty(key);
    }
}
