package com.Devansh.Authentication_System.controller;

import com.Devansh.Authentication_System.io.AuthRequest;
import com.Devansh.Authentication_System.io.AuthResponse;
import com.Devansh.Authentication_System.io.ResetPasswordRequest;
import com.Devansh.Authentication_System.security.RateLimiter;
import com.Devansh.Authentication_System.security.TokenBlacklist;
import com.Devansh.Authentication_System.service.AppUserDetailsService;
import com.Devansh.Authentication_System.service.ProfileService;
import com.Devansh.Authentication_System.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Authentication uses the "Authorization: Bearer <token>" header only.
 * The token is returned in the login response body; no cookie is set.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final AppUserDetailsService appUserDetailsService;
    private final JwtUtil jwtUtil;
    private final ProfileService profileService;
    private final RateLimiter rateLimiter;
    private final TokenBlacklist tokenBlacklist;

    // ==========================================
    // LOGIN / LOGOUT
    // ==========================================

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody AuthRequest request,
            HttpServletRequest http) {

        // Checked before the try block so a 429 is not turned into a 401
        rateLimiter.check(
                "login:ip:" + http.getRemoteAddr(),
                30,
                Duration.ofMinutes(5)
        );
        rateLimiter.check(
                "login:email:" + request.getEmail(),
                10,
                Duration.ofMinutes(15)
        );

        try {

            authenticate(request.getEmail(), request.getPassword());

            final UserDetails userDetails =
                    appUserDetailsService.loadUserByUsername(request.getEmail());

            final String jwtToken = jwtUtil.generateToken(userDetails);

            // Lets the client decide whether to show the verify-OTP page
            Boolean verified = profileService
                    .getProfile(request.getEmail())
                    .getIsAccountVerified();

            return ResponseEntity.ok(
                    new AuthResponse(request.getEmail(), jwtToken, verified)
            );

        } catch (DisabledException ex) {

            return error(HttpStatus.UNAUTHORIZED, "Authentication is disabled");

        } catch (Exception ex) {

            return error(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        }
    }

    /**
     * Revokes the token used for this request. The client must also delete
     * its stored copy.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader("Authorization") String authorizationHeader) {

        if (authorizationHeader.startsWith("Bearer ")) {

            String token = authorizationHeader.substring(7);

            tokenBlacklist.revoke(
                    jwtUtil.extractJti(token),
                    jwtUtil.extractExpiration(token)
            );
        }

        return ok("Logged out successfully");
    }

    private Authentication authenticate(String email, String password) {

        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );
    }

    @GetMapping("/isAuthenticated")
    public ResponseEntity<Boolean> isAuthenticated(
            @CurrentSecurityContext(expression = "authentication")
            Authentication authentication) {

        boolean isAuthenticated =
                authentication != null
                        && authentication.isAuthenticated()
                        && !(authentication instanceof AnonymousAuthenticationToken);

        return ResponseEntity.ok(isAuthenticated);
    }

    // ==========================================
    // PASSWORD RESET (public)
    // ==========================================

    /**
     * Always answers the same way, whether or not the email is registered.
     */
    @PostMapping("/send-reset-otp")
    public ResponseEntity<?> sendResetOtp(
            @RequestParam("email") String email,
            HttpServletRequest http) {

        rateLimiter.check(
                "reset-otp:ip:" + http.getRemoteAddr(),
                10,
                Duration.ofMinutes(15)
        );
        rateLimiter.check(
                "reset-otp:email:" + email,
                3,
                Duration.ofMinutes(15)
        );

        profileService.sendResetOtp(email);

        return ok("If an account exists for this email, an OTP has been sent.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest http) {

        rateLimiter.check(
                "reset-password:ip:" + http.getRemoteAddr(),
                10,
                Duration.ofMinutes(15)
        );
        rateLimiter.check(
                "reset-password:email:" + request.getEmail(),
                10,
                Duration.ofMinutes(15)
        );

        // Service exceptions keep their own status (400, 429, ...)
        profileService.resetPassword(
                request.getEmail(),
                request.getOtp(),
                request.getNewPassword()
        );

        return ok("Password reset successfully");
    }

    // ==========================================
    // ACCOUNT VERIFICATION (needs a token)
    // ==========================================

    @PostMapping("/send-otp")
    public ResponseEntity<?> sendVerifyOtp(
            @CurrentSecurityContext(expression = "authentication?.name")
            String email) {

        rateLimiter.check(
                "send-otp:email:" + email,
                3,
                Duration.ofMinutes(10)
        );

        profileService.sendOtp(email);

        return ok("Verification OTP sent");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyEmail(
            @RequestBody Map<String, Object> request,
            @CurrentSecurityContext(expression = "authentication?.name")
            String email) {

        rateLimiter.check(
                "verify-otp:email:" + email,
                10,
                Duration.ofMinutes(10)
        );

        Object otpValue = request.get("otp");

        if (otpValue == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "OTP is required"
            );
        }

        profileService.verifyOtp(email, otpValue.toString());

        return ok("Email verified successfully");
    }

    // ==========================================
    // HELPERS
    // ==========================================

    private ResponseEntity<Map<String, Object>> ok(String message) {

        Map<String, Object> body = new HashMap<>();
        body.put("error", false);
        body.put("message", message);

        return ResponseEntity.ok(body);
    }

    private ResponseEntity<Map<String, Object>> error(
            HttpStatus status, String message) {

        Map<String, Object> body = new HashMap<>();
        body.put("error", true);
        body.put("message", message);

        return ResponseEntity.status(status).body(body);
    }
}
