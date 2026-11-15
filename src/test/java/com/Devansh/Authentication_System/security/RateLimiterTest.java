package com.Devansh.Authentication_System.security;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {

    private final RateLimiter limiter = new RateLimiter();

    @Test
    void allowsRequestsUpToTheLimitThenReturns429() {
        Duration window = Duration.ofMinutes(1);

        limiter.check("k", 3, window);
        limiter.check("k", 3, window);
        limiter.check("k", 3, window);

        ResponseStatusException ex = assertThrows(
                ResponseStatusException.class,
                () -> limiter.check("k", 3, window)
        );

        assertEquals(HttpStatus.TOO_MANY_REQUESTS.value(), ex.getStatusCode().value());
    }

    @Test
    void keysAreIndependent() {
        Duration window = Duration.ofMinutes(1);

        limiter.check("a", 1, window);

        assertDoesNotThrow(() -> limiter.check("b", 1, window));
    }

    @Test
    void windowExpires() throws InterruptedException {
        Duration window = Duration.ofMillis(50);

        limiter.check("k", 1, window);
        Thread.sleep(80);

        assertDoesNotThrow(() -> limiter.check("k", 1, window));
    }
}
