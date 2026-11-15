package com.Devansh.Authentication_System.service;

import com.Devansh.Authentication_System.entity.UserEntity;
import com.Devansh.Authentication_System.io.ProfileRequest;
import com.Devansh.Authentication_System.repository.UserRepository;
import com.Devansh.Authentication_System.security.OtpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mail.MailSendException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class ProfileServiceImplTest {

    private final Map<String, UserEntity> db = new HashMap<>();

    private final UserRepository repository = mock(UserRepository.class);
    private final EmailServices emailServices = mock(EmailServices.class);
    private final PasswordEncoder encoder = new BCryptPasswordEncoder();
    private final OtpService otpService = new OtpService("unit-test-secret");

    private ProfileServiceImpl service;

    @BeforeEach
    void setUp() {
        when(repository.save(any(UserEntity.class))).thenAnswer(inv -> {
            UserEntity u = inv.getArgument(0);
            db.put(u.getEmail(), u);
            return u;
        });
        when(repository.findByEmail(anyString())).thenAnswer(inv ->
                Optional.ofNullable(db.get((String) inv.getArgument(0))));
        when(repository.existsByEmail(anyString())).thenAnswer(inv ->
                db.containsKey((String) inv.getArgument(0)));

        service = new ProfileServiceImpl(
                repository, encoder, emailServices, otpService);
    }

    private static <T> T any(Class<T> type) {
        return org.mockito.ArgumentMatchers.any(type);
    }

    private ProfileRequest request() {
        return new ProfileRequest("Devansh", "dev@example.test", "Password@123");
    }

    /** Registers a user and returns the plain OTP that was emailed. */
    private String registerAndGetOtp() {
        service.createProfile(request());

        ArgumentCaptor<String> otp = ArgumentCaptor.forClass(String.class);
        verify(emailServices).sendOtpEmail(anyString(), otp.capture());
        return otp.getValue();
    }

    // ---------- registration ----------

    @Test
    void registrationRejectsDuplicateEmail() {
        service.createProfile(request());

        ResponseStatusException ex = assertThrows(
                ResponseStatusException.class,
                () -> service.createProfile(request()));

        assertEquals(409, ex.getStatusCode().value());
    }

    @Test
    void registrationStoresAHashedOtpAndSendsOnlyTheOtpEmail() {
        String otp = registerAndGetOtp();

        UserEntity user = db.get("dev@example.test");
        assertNotEquals(otp, user.getVerifyOtp());
        assertTrue(otpService.matches(otp, user.getVerifyOtp()));
        assertFalse(user.getIsAccountVerified());
        verify(emailServices, never()).sendWelcomeMail(anyString(), anyString());
    }

    @Test
    void registrationFailsWhenTheOtpEmailCannotBeSent() {
        doThrow(new MailSendException("down"))
                .when(emailServices).sendOtpEmail(anyString(), anyString());

        ResponseStatusException ex = assertThrows(
                ResponseStatusException.class,
                () -> service.createProfile(request()));

        assertEquals(500, ex.getStatusCode().value());
    }

    // ---------- verify OTP ----------

    @Test
    void correctOtpVerifiesTheAccountAndSendsTheWelcomeEmail() {
        String otp = registerAndGetOtp();

        service.verifyOtp("dev@example.test", otp);

        UserEntity user = db.get("dev@example.test");
        assertTrue(user.getIsAccountVerified());
        assertNull(user.getVerifyOtp());
        verify(emailServices).sendWelcomeMail("dev@example.test", "Devansh");
    }

    @Test
    void failingWelcomeEmailDoesNotUndoVerification() {
        String otp = registerAndGetOtp();
        doThrow(new MailSendException("down"))
                .when(emailServices).sendWelcomeMail(anyString(), anyString());

        assertDoesNotThrow(() -> service.verifyOtp("dev@example.test", otp));
        assertTrue(db.get("dev@example.test").getIsAccountVerified());
    }

    @Test
    void wrongOtpIsRejectedAndCounted() {
        registerAndGetOtp();

        ResponseStatusException ex = assertThrows(
                ResponseStatusException.class,
                () -> service.verifyOtp("dev@example.test", "000000"));

        assertEquals(400, ex.getStatusCode().value());
        assertEquals(1, db.get("dev@example.test").getVerifyOtpAttempts());
    }

    @Test
    void otpIsInvalidatedAfterTooManyWrongAttempts() {
        String otp = registerAndGetOtp();

        for (int i = 0; i < ProfileServiceImpl.MAX_OTP_ATTEMPTS - 1; i++) {
            assertThrows(ResponseStatusException.class,
                    () -> service.verifyOtp("dev@example.test", "000000"));
        }

        ResponseStatusException locked = assertThrows(
                ResponseStatusException.class,
                () -> service.verifyOtp("dev@example.test", "000000"));
        assertEquals(429, locked.getStatusCode().value());

        // The correct OTP no longer works either
        ResponseStatusException afterLock = assertThrows(
                ResponseStatusException.class,
                () -> service.verifyOtp("dev@example.test", otp));
        assertEquals(400, afterLock.getStatusCode().value());
    }

    @Test
    void expiredOtpIsRejected() {
        String otp = registerAndGetOtp();
        db.get("dev@example.test")
                .setVerifyOtpExpireAt(System.currentTimeMillis() - 1);

        ResponseStatusException ex = assertThrows(
                ResponseStatusException.class,
                () -> service.verifyOtp("dev@example.test", otp));

        assertEquals(400, ex.getStatusCode().value());
    }

    // ---------- reset password ----------

    private String requestResetOtp() {
        service.createProfile(request());
        service.sendResetOtp("dev@example.test");

        ArgumentCaptor<String> otp = ArgumentCaptor.forClass(String.class);
        verify(emailServices).sendResetPasswordMailAsync(anyString(), otp.capture());
        return otp.getValue();
    }

    @Test
    void resetOtpForUnknownEmailIsSilentAndSendsNothing() {
        assertDoesNotThrow(() -> service.sendResetOtp("nobody@example.test"));

        verify(emailServices, never())
                .sendResetPasswordMailAsync(anyString(), anyString());
    }

    @Test
    void resetPasswordWithCorrectOtpChangesThePassword() {
        String otp = requestResetOtp();

        service.resetPassword("dev@example.test", otp, "NewPassword@456");

        UserEntity user = db.get("dev@example.test");
        assertTrue(encoder.matches("NewPassword@456", user.getPassword()));
        assertNull(user.getResetOtp());
    }

    @Test
    void resetPasswordWithWrongOtpIsABadRequestNotAServerError() {
        requestResetOtp();

        ResponseStatusException ex = assertThrows(
                ResponseStatusException.class,
                () -> service.resetPassword(
                        "dev@example.test", "000000", "NewPassword@456"));

        assertEquals(400, ex.getStatusCode().value());
    }

    @Test
    void resetPasswordForUnknownEmailGivesTheSameAnswerAsAWrongOtp() {
        ResponseStatusException ex = assertThrows(
                ResponseStatusException.class,
                () -> service.resetPassword(
                        "nobody@example.test", "123456", "NewPassword@456"));

        assertEquals(400, ex.getStatusCode().value());
        assertEquals("Invalid or expired OTP", ex.getReason());
    }

    @Test
    void resetPasswordRejectsReusingTheCurrentPassword() {
        String otp = requestResetOtp();

        ResponseStatusException ex = assertThrows(
                ResponseStatusException.class,
                () -> service.resetPassword(
                        "dev@example.test", otp, "Password@123"));

        assertEquals(400, ex.getStatusCode().value());
    }

    @Test
    void resetOtpIsInvalidatedAfterTooManyWrongAttempts() {
        String otp = requestResetOtp();

        for (int i = 0; i < ProfileServiceImpl.MAX_OTP_ATTEMPTS - 1; i++) {
            assertThrows(ResponseStatusException.class, () ->
                    service.resetPassword(
                            "dev@example.test", "000000", "NewPassword@456"));
        }

        ResponseStatusException locked = assertThrows(
                ResponseStatusException.class, () ->
                        service.resetPassword(
                                "dev@example.test", "000000", "NewPassword@456"));
        assertEquals(429, locked.getStatusCode().value());

        assertThrows(ResponseStatusException.class, () ->
                service.resetPassword(
                        "dev@example.test", otp, "NewPassword@456"));
    }
}
