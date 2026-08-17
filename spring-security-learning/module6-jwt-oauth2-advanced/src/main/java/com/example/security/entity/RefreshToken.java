package com.example.security.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * CONCEPT: Refresh Token Persistence
 *
 * Why store refresh tokens in the database?
 *
 * 1. REVOCATION: JWTs cannot be invalidated once issued (they're stateless).
 *    Storing the refresh token lets you revoke it immediately (logout, security incident).
 *
 * 2. ROTATION: Each time a refresh token is used, issue a new one and
 *    mark the old as used. If the old one is used again → someone stole it → revoke all.
 *    This is "Refresh Token Rotation" — the security standard recommended by OAuth 2.1.
 *
 * 3. FAMILY TRACKING: Group related tokens (a "family") issued in one session.
 *    If any member of the family is reused after rotation → revoke the entire family.
 *    This detects token theft even when the attacker uses the token before the victim.
 *
 * Refresh Token Storage Schema:
 * ┌────────────────────────────────────────────────────────────────┐
 * │ id          : UUID primary key                                  │
 * │ token       : The actual token value (random, not a JWT)       │
 * │ username    : Which user this token belongs to                  │
 * │ family_id   : UUID linking all tokens from one login session    │
 * │ expires_at  : When this token expires (7-30 days typically)    │
 * │ revoked     : Soft delete — true = token is invalidated        │
 * │ created_at  : Audit field                                      │
 * └────────────────────────────────────────────────────────────────┘
 *
 * Lifecycle:
 * LOGIN  → create RefreshToken(family=new UUID)
 * REFRESH → validate token, create NEW RefreshToken(same family),
 *           mark old token as revoked
 * LOGOUT → revoke ALL tokens in the family
 * THEFT  → old token used after rotation → revoke entire family
 */
@Entity
@Table(name = "refresh_tokens", indexes = {
    @Index(name = "idx_token", columnList = "token"),
    @Index(name = "idx_username", columnList = "username"),
    @Index(name = "idx_family", columnList = "family_id")
})
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(unique = true, nullable = false, length = 512)
    private String token;

    @Column(nullable = false)
    private String username;

    @Column(name = "family_id", nullable = false)
    private String familyId;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public RefreshToken() {}

    public RefreshToken(String token, String username, String familyId, Instant expiresAt) {
        this.token = token;
        this.username = username;
        this.familyId = familyId;
        this.expiresAt = expiresAt;
    }

    public String getId() { return id; }
    public String getToken() { return token; }
    public String getUsername() { return username; }
    public String getFamilyId() { return familyId; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
    public Instant getCreatedAt() { return createdAt; }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
