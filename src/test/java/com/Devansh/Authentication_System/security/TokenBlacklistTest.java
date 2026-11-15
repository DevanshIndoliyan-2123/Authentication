package com.Devansh.Authentication_System.security;

import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class TokenBlacklistTest {

    private final TokenBlacklist blacklist = new TokenBlacklist();

    @Test
    void revokedTokenIsRejectedUntilItExpires() {
        blacklist.revoke("jti-1", new Date(System.currentTimeMillis() + 60_000));

        assertTrue(blacklist.isRevoked("jti-1"));
        assertFalse(blacklist.isRevoked("jti-2"));
    }

    @Test
    void expiredEntriesAreForgotten() {
        blacklist.revoke("jti-1", new Date(System.currentTimeMillis() - 1));

        assertFalse(blacklist.isRevoked("jti-1"));
    }

    @Test
    void nullIdIsNeverRevoked() {
        assertFalse(blacklist.isRevoked(null));
    }
}
