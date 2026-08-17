package com.example.security.service;

import com.example.security.entity.RefreshToken;
import com.example.security.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * CONCEPT: Refresh Token Rotation with Theft Detection
 *
 * Refresh Token Flow:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │ 1. LOGIN                                                             │
 * │    → Issue ACCESS token (15 min, JWT, stateless)                   │
 * │    → Issue REFRESH token (7 days, opaque, stored in DB)            │
 * │    → Create token family (UUID) to link this session's tokens       │
 * │                                                                     │
 * │ 2. ACCESS TOKEN EXPIRES                                             │
 * │    Client sends: POST /auth/refresh {refreshToken: "abc123"}        │
 * │    Server:                                                          │
 * │      a. Look up refresh token in DB                                 │
 * │      b. Verify: not expired, not revoked                           │
 * │      c. Issue NEW access token                                      │
 * │      d. Issue NEW refresh token (with same familyId)               │
 * │      e. Mark OLD refresh token as revoked (ROTATION!)              │
 * │                                                                     │
 * │ 3. THEFT DETECTION                                                  │
 * │    If an already-rotated (revoked) refresh token is used:           │
 * │      → Attacker stole the token before victim rotated it           │
 * │      → OR victim's old token leaked                                │
 * │    Response: REVOKE THE ENTIRE FAMILY → forces re-login            │
 * │                                                                     │
 * │ 4. LOGOUT                                                           │
 * │    Revoke all tokens in the family → all devices logged out        │
 * │    (If you want single-device logout, only revoke that token)      │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Why OPAQUE refresh tokens (not JWTs)?
 * - Can be revoked instantly (just flip a DB flag)
 * - JWT refresh tokens cannot be invalidated without a blacklist
 * - If the refresh JWT is stolen, attacker can use it until it expires
 * - Opaque token: stolen token is invalid as soon as we detect and revoke
 */
@Service
@Transactional
public class RefreshTokenService {

    private final RefreshTokenRepository tokenRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${jwt.refresh-expiration-seconds:604800}") // 7 days
    private long refreshExpirationSeconds;

    public RefreshTokenService(RefreshTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    /**
     * Creates the initial refresh token on login. Starts a new token family.
     */
    public RefreshToken createRefreshToken(UserDetails userDetails) {
        String tokenValue = generateSecureToken();
        String familyId = UUID.randomUUID().toString(); // new family on each login
        Instant expiry = Instant.now().plusSeconds(refreshExpirationSeconds);

        RefreshToken token = new RefreshToken(tokenValue, userDetails.getUsername(),
                                              familyId, expiry);
        return tokenRepository.save(token);
    }

    /**
     * Rotates the refresh token:
     * 1. Validates the old token
     * 2. Detects theft if already revoked
     * 3. Revokes old, issues new token with same familyId
     */
    public RefreshToken rotateRefreshToken(String oldTokenValue) {
        RefreshToken oldToken = tokenRepository.findByToken(oldTokenValue)
            .orElseThrow(() -> new RefreshTokenException("Refresh token not found"));

        // THEFT DETECTION: token already revoked = replay attack
        if (oldToken.isRevoked()) {
            // This refresh token was already used! Possible theft.
            // Revoke the ENTIRE family to force re-login on all devices.
            tokenRepository.revokeAllByFamilyId(oldToken.getFamilyId());
            throw new RefreshTokenException(
                "Refresh token reuse detected — entire session revoked. Please log in again.");
        }

        if (oldToken.isExpired()) {
            throw new RefreshTokenException("Refresh token has expired");
        }

        // Revoke the old token (rotation step)
        oldToken.setRevoked(true);
        tokenRepository.save(oldToken);

        // Issue new refresh token with SAME familyId (preserves session lineage)
        String newTokenValue = generateSecureToken();
        RefreshToken newToken = new RefreshToken(
            newTokenValue,
            oldToken.getUsername(),
            oldToken.getFamilyId(), // same family
            Instant.now().plusSeconds(refreshExpirationSeconds)
        );
        return tokenRepository.save(newToken);
    }

    /**
     * Revoke all tokens for a session family (logout).
     */
    public void revokeFamily(String tokenValue) {
        tokenRepository.findByToken(tokenValue).ifPresent(token ->
            tokenRepository.revokeAllByFamilyId(token.getFamilyId())
        );
    }

    /**
     * Revoke all tokens for a user (password change, account compromise).
     */
    public void revokeAllForUser(String username) {
        tokenRepository.revokeAllByUsername(username);
    }

    /**
     * Scheduled cleanup: remove expired tokens from the database.
     * Runs every hour. Prevents the refresh_tokens table from growing forever.
     */
    @Scheduled(fixedRate = 3_600_000) // every 1 hour
    public void cleanupExpiredTokens() {
        int deleted = tokenRepository.deleteExpiredTokens(Instant.now());
        if (deleted > 0) {
            System.out.println("Cleaned up " + deleted + " expired refresh tokens");
        }
    }

    /**
     * Generates a cryptographically secure random token.
     * 32 bytes (256 bits) of randomness → Base64URL encoded → 43 chars.
     * SecureRandom is thread-safe and uses OS entropy sources.
     *
     * Why NOT use UUID? UUID v4 has only 122 bits of randomness.
     * Why NOT use JWT? Opaque tokens can be revoked.
     */
    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static class RefreshTokenException extends RuntimeException {
        public RefreshTokenException(String message) {
            super(message);
        }
    }
}
