package com.example.security.service;

import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Brute force protection via progressive account lockout.
 *
 * Strategy:
 * - Track failed login attempts per user in the database
 * - Lock account after N consecutive failures
 * - Automatically unlock after a configurable duration
 * - Reset counter on successful login
 *
 * Why DB-backed (not in-memory)?
 * - Survives server restarts
 * - Works in clustered / multi-instance deployments
 * - Provides audit trail
 *
 * Alternative strategies:
 * - IP-based rate limiting (covers unknown usernames too)
 * - Redis-backed counters (faster, but in-memory)
 * - CAPTCHA after N failures
 * - Progressive delays (exponential backoff)
 */
@Service
@Transactional
public class BruteForceProtectionService {

    private final UserRepository userRepository;

    @Value("${security.max-login-attempts:5}")
    private int maxAttempts;

    @Value("${security.lockout-duration-minutes:15}")
    private int lockoutMinutes;

    public BruteForceProtectionService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void recordFailedAttempt(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            autoUnlockIfExpired(user);

            user.incrementFailedAttempts();

            if (user.getFailedLoginAttempts() >= maxAttempts) {
                Instant lockoutTime = Instant.now().plus(lockoutMinutes, ChronoUnit.MINUTES);
                user.lock(lockoutTime);
            }

            userRepository.save(user);
        });
    }

    public void recordSuccessfulLogin(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            user.resetFailedAttempts();
            user.unlock();
            userRepository.save(user);
        });
    }

    /**
     * Checks lockout status. If lockout period has expired, automatically unlocks.
     * Returns true if the account is currently locked (lockout not yet expired).
     */
    @Transactional(readOnly = true)
    public boolean isLocked(String username) {
        return userRepository.findByUsername(username)
            .map(user -> {
                if (!user.isAccountLocked()) return false;
                if (user.getLockoutTime() != null && Instant.now().isAfter(user.getLockoutTime())) {
                    // Lockout expired — unlock lazily on next check
                    return false;
                }
                return true;
            })
            .orElse(false);
    }

    public void autoUnlockIfExpired(User user) {
        if (user.isAccountLocked()
                && user.getLockoutTime() != null
                && Instant.now().isAfter(user.getLockoutTime())) {
            user.unlock();
        }
    }

    public int getRemainingAttempts(String username) {
        return userRepository.findByUsername(username)
            .map(u -> Math.max(0, maxAttempts - u.getFailedLoginAttempts()))
            .orElse(maxAttempts);
    }
}
