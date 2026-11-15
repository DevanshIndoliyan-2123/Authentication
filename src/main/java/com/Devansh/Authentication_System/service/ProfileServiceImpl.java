package com.Devansh.Authentication_System.service;

import com.Devansh.Authentication_System.entity.UserEntity;
import com.Devansh.Authentication_System.io.ProfileRequest;
import com.Devansh.Authentication_System.io.ProfileResponse;
import com.Devansh.Authentication_System.repository.UserRepository;
import com.Devansh.Authentication_System.security.OtpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProfileServiceImpl implements ProfileService {

    static final long OTP_EXPIRY_TIME = 5 * 60 * 1000L;
    static final int MAX_OTP_ATTEMPTS = 5;
    static final int MIN_PASSWORD_LENGTH = 8;

    private static final String INVALID_OTP = "Invalid or expired OTP";
    private static final String TOO_MANY_ATTEMPTS =
            "Too many incorrect attempts. Please request a new OTP.";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailServices emailServices;
    private final OtpService otpService;


    // ==========================================
    // 1. REGISTER USER + SEND VERIFICATION OTP
    // ==========================================

    /**
     * Saves the user and sends the verification OTP in one transaction.
     * If the OTP email cannot be sent, the signup is rolled back, so the
     * person can simply register again with the same email.
     */
    @Override
    @Transactional
    public ProfileResponse createProfile(ProfileRequest request) {

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Email already exists"
            );
        }

        UserEntity saved = userRepository.save(
                convertToUserEntity(request)
        );

        // Any failure here rolls the new user back
        sendOtp(saved.getEmail());

        return convertToProfileResponse(saved);
    }


    // ==========================================
    // 2. SEND PASSWORD RESET OTP
    // ==========================================

    /**
     * Never reveals whether the email is registered: unknown emails return
     * normally, and the email is sent in the background.
     */
    @Override
    public void sendResetOtp(String email) {

        Optional<UserEntity> found = userRepository.findByEmail(email);

        if (found.isEmpty()) {
            log.debug("Password reset requested for an unknown email");
            return;
        }

        UserEntity user = found.get();

        String otp = otpService.generate();

        user.setResetOtp(otpService.hash(otp));
        user.setResetOtpExpireAt(System.currentTimeMillis() + OTP_EXPIRY_TIME);
        user.setResetOtpAttempts(0);

        userRepository.save(user);

        emailServices.sendResetPasswordMailAsync(user.getEmail(), otp);
    }


    // ==========================================
    // 3. RESET PASSWORD
    // ==========================================

    @Override
    public void resetPassword(
            String email,
            String otp,
            String newPassword
    ) {

        // Same answer for unknown email and wrong OTP
        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.BAD_REQUEST,
                                INVALID_OTP
                        )
                );

        long now = System.currentTimeMillis();

        if (user.getResetOtp() == null
                || user.getResetOtpExpireAt() == null
                || user.getResetOtpExpireAt() <= now) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    INVALID_OTP
            );
        }

        if (!otpService.matches(otp, user.getResetOtp())) {

            int attempts = zeroIfNull(user.getResetOtpAttempts()) + 1;

            if (attempts >= MAX_OTP_ATTEMPTS) {
                user.setResetOtp(null);
                user.setResetOtpExpireAt(0L);
                user.setResetOtpAttempts(0);
                userRepository.save(user);

                throw new ResponseStatusException(
                        HttpStatus.TOO_MANY_REQUESTS,
                        TOO_MANY_ATTEMPTS
                );
            }

            user.setResetOtpAttempts(attempts);
            userRepository.save(user);

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    INVALID_OTP
            );
        }

        if (newPassword == null
                || newPassword.length() < MIN_PASSWORD_LENGTH) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "New password must be at least "
                            + MIN_PASSWORD_LENGTH + " characters long"
            );
        }

        if (passwordEncoder.matches(newPassword, user.getPassword())) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "New password cannot be the same as the old password"
            );
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetOtp(null);
        user.setResetOtpExpireAt(0L);
        user.setResetOtpAttempts(0);

        userRepository.save(user);
    }


    // ==========================================
    // 4. SEND ACCOUNT VERIFICATION OTP
    // ==========================================

    @Override
    public void sendOtp(String email) {

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "User not found"
                        )
                );

        if (Boolean.TRUE.equals(user.getIsAccountVerified())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Account is already verified"
            );
        }

        String otp = otpService.generate();

        user.setVerifyOtp(otpService.hash(otp));
        user.setVerifyOtpExpireAt(System.currentTimeMillis() + OTP_EXPIRY_TIME);
        user.setVerifyOtpAttempts(0);

        userRepository.save(user);

        try {
            emailServices.sendOtpEmail(user.getEmail(), otp);
        } catch (Exception ex) {
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to send verification OTP",
                    ex
            );
        }
    }


    // ==========================================
    // 5. VERIFY OTP
    // ==========================================

    @Override
    public void verifyOtp(String email, String otp) {

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "User not found"
                        )
                );

        if (Boolean.TRUE.equals(user.getIsAccountVerified())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Account is already verified"
            );
        }

        long now = System.currentTimeMillis();

        if (user.getVerifyOtp() == null
                || user.getVerifyOtpExpireAt() == null
                || user.getVerifyOtpExpireAt() <= now) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    INVALID_OTP
            );
        }

        if (!otpService.matches(otp, user.getVerifyOtp())) {

            int attempts = zeroIfNull(user.getVerifyOtpAttempts()) + 1;

            if (attempts >= MAX_OTP_ATTEMPTS) {
                user.setVerifyOtp(null);
                user.setVerifyOtpExpireAt(0L);
                user.setVerifyOtpAttempts(0);
                userRepository.save(user);

                throw new ResponseStatusException(
                        HttpStatus.TOO_MANY_REQUESTS,
                        TOO_MANY_ATTEMPTS
                );
            }

            user.setVerifyOtpAttempts(attempts);
            userRepository.save(user);

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    INVALID_OTP
            );
        }

        user.setIsAccountVerified(true);
        user.setVerifyOtp(null);
        user.setVerifyOtpExpireAt(0L);
        user.setVerifyOtpAttempts(0);

        userRepository.save(user);

        // The account is already verified; a failing welcome email must
        // not turn a successful verification into an error.
        try {
            emailServices.sendWelcomeMail(user.getEmail(), user.getName());
        } catch (Exception ex) {
            log.warn("Account verified, but welcome email failed: {}",
                    ex.getMessage());
        }
    }


    // ==========================================
    // 6. GET USER PROFILE
    // ==========================================

    @Override
    public ProfileResponse getProfile(String email) {

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "User not found"
                        )
                );

        return convertToProfileResponse(user);
    }


    // ==========================================
    // 7. HELPERS
    // ==========================================

    private int zeroIfNull(Integer value) {
        return value == null ? 0 : value;
    }

    private ProfileResponse convertToProfileResponse(UserEntity user) {

        return ProfileResponse.builder()
                .name(user.getName())
                .email(user.getEmail())
                .userId(user.getUserId())
                .isAccountVerified(user.getIsAccountVerified())
                .build();
    }

    private UserEntity convertToUserEntity(ProfileRequest request) {

        return UserEntity.builder()
                .email(request.getEmail())
                .userId(UUID.randomUUID().toString())
                .name(request.getName())
                .password(passwordEncoder.encode(request.getPassword()))
                .isAccountVerified(false)
                .resetOtpExpireAt(0L)
                .resetOtp(null)
                .verifyOtp(null)
                .verifyOtpExpireAt(0L)
                .build();
    }
}
