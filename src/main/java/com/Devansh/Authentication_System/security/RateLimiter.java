package com.Devansh.Authentication_System.security;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Small in-memory sliding-window rate limiter.
 *
 * It is per application instance: counters reset on restart and are not
 * shared between instances. For a multi-instance deployment, move this to
 * Redis or an API gateway.
 */
@Component
public class RateLimiter {

    private static final long MAX_RETENTION_MS = Duration.ofHours(1).toMillis();
    private static final int PURGE_THRESHOLD = 10_000;

    private final Map<String, Deque<Long>> hits = new ConcurrentHashMap<>();

    /**
     * Records one hit for the key and throws 429 when the key has already
     * made {@code maxRequests} hits inside the window.
     */
    public void check(String key, int maxRequests, Duration window) {

        long now = System.currentTimeMillis();
        long cutoff = now - window.toMillis();

        Deque<Long> timestamps =
                hits.computeIfAbsent(key, k -> new ArrayDeque<>());

        synchronized (timestamps) {

            while (!timestamps.isEmpty() && timestamps.peekFirst() < cutoff) {
                timestamps.pollFirst();
            }

            if (timestamps.size() >= maxRequests) {
                throw new ResponseStatusException(
                        HttpStatus.TOO_MANY_REQUESTS,
                        "Too many requests. Please try again later."
                );
            }

            timestamps.addLast(now);
        }

        if (hits.size() > PURGE_THRESHOLD) {
            purge(now);
        }
    }

    /** Clears all counters (used by tests). */
    public void reset() {
        hits.clear();
    }

    private void purge(long now) {
        hits.entrySet().removeIf(entry -> {
            synchronized (entry.getValue()) {
                Long last = entry.getValue().peekLast();
                return last == null || last < now - MAX_RETENTION_MS;
            }
        });
    }
}
