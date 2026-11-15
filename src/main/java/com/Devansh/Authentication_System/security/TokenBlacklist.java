package com.Devansh.Authentication_System.security;

import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Remembers the ids (jti) of tokens revoked by logout until they expire.
 *
 * In-memory: revoked tokens become valid again after a restart (and are not
 * shared between instances). Tokens are short-lived, so this is acceptable
 * for a single instance; use Redis or a DB table for more.
 */
@Component
public class TokenBlacklist {

    private final Map<String, Long> revoked = new ConcurrentHashMap<>();

    public void revoke(String jti, Date expiresAt) {

        if (jti == null || expiresAt == null) {
            return;
        }

        purgeExpired();
        revoked.put(jti, expiresAt.getTime());
    }

    public boolean isRevoked(String jti) {

        if (jti == null) {
            return false;
        }

        Long expiresAt = revoked.get(jti);

        if (expiresAt == null) {
            return false;
        }

        if (expiresAt < System.currentTimeMillis()) {
            revoked.remove(jti);
            return false;
        }

        return true;
    }

    private void purgeExpired() {
        long now = System.currentTimeMillis();
        revoked.values().removeIf(expiresAt -> expiresAt < now);
    }
}
