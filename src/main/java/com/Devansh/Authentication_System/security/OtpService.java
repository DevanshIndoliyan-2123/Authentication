package com.Devansh.Authentication_System.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Generates six-digit OTPs and stores them only as keyed hashes
 * (HMAC-SHA256), so a leaked database row cannot be used as an OTP.
 */
@Component
public class OtpService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] key;

    public OtpService(@Value("${otp.secret}") String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("otp.secret must not be blank");
        }
        this.key = secret.getBytes(StandardCharsets.UTF_8);
    }

    /** Returns a random six-digit OTP (100000-999999). */
    public String generate() {
        return String.valueOf(RANDOM.nextInt(900000) + 100000);
    }

    /** Returns the hex HMAC-SHA256 of the OTP. */
    public String hash(String otp) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            byte[] digest = mac.doFinal(otp.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Could not hash OTP", ex);
        }
    }

    /** Constant-time comparison of a supplied OTP with a stored hash. */
    public boolean matches(String otp, String storedHash) {
        if (otp == null || storedHash == null) {
            return false;
        }
        return MessageDigest.isEqual(
                hash(otp).getBytes(StandardCharsets.UTF_8),
                storedHash.getBytes(StandardCharsets.UTF_8)
        );
    }
}
