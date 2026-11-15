package com.Devansh.Authentication_System.controller;

import com.Devansh.Authentication_System.io.ProfileRequest;
import com.Devansh.Authentication_System.io.ProfileResponse;
import com.Devansh.Authentication_System.security.RateLimiter;
import com.Devansh.Authentication_System.service.ProfileService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1")
public class ProfileController {

    private final ProfileService profileService;
    private final RateLimiter rateLimiter;

    /**
     * Creates the account and sends the verification OTP. The welcome email
     * is sent only after the OTP is verified (see ProfileServiceImpl).
     */
    @PostMapping("/register")
    public ResponseEntity<ProfileResponse> register(
            @Valid @RequestBody ProfileRequest request,
            HttpServletRequest http) {

        rateLimiter.check(
                "register:ip:" + http.getRemoteAddr(),
                10,
                Duration.ofMinutes(10)
        );

        return ResponseEntity.ok(profileService.createProfile(request));
    }

    /** Public liveness check. */
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }

    @GetMapping("/profile")
    public ProfileResponse getProfile(
            @CurrentSecurityContext(
                    expression = "authentication.name"
            )
            String email) {

        return profileService.getProfile(email);
    }
}
