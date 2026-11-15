package com.Devansh.Authentication_System.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OtpServiceTest {

    private final OtpService otpService = new OtpService("unit-test-secret");

    @Test
    void generatesSixDigitCodes() {
        for (int i = 0; i < 200; i++) {
            assertTrue(otpService.generate().matches("[1-9]\\d{5}"));
        }
    }

    @Test
    void hashIsNotThePlainOtpAndIsStable() {
        String hash = otpService.hash("123456");

        assertNotEquals("123456", hash);
        assertEquals(64, hash.length());
        assertEquals(hash, otpService.hash("123456"));
    }

    @Test
    void matchesOnlyTheSameOtp() {
        String hash = otpService.hash("123456");

        assertTrue(otpService.matches("123456", hash));
        assertFalse(otpService.matches("654321", hash));
        assertFalse(otpService.matches(null, hash));
        assertFalse(otpService.matches("123456", null));
    }

    @Test
    void differentSecretsGiveDifferentHashes() {
        assertNotEquals(
                otpService.hash("123456"),
                new OtpService("another-secret").hash("123456")
        );
    }

    @Test
    void blankSecretIsRejected() {
        assertThrows(IllegalStateException.class, () -> new OtpService(" "));
    }
}
