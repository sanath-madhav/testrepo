package com.example.security.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * CONCEPT: JSON Web Token (JWT)
 *
 * JWT Structure: header.payload.signature
 * Each part is Base64URL encoded.
 *
 * ┌─────────────────────────────────────────────────────────┐
 * │ HEADER (algorithm + token type)                         │
 * │ { "alg": "HS256", "typ": "JWT" }                       │
 * ├─────────────────────────────────────────────────────────┤
 * │ PAYLOAD (claims = statements about user + metadata)     │
 * │ {                                                       │
 * │   "sub": "username",    <- subject (who)               │
 * │   "iat": 1710000000,    <- issued at                   │
 * │   "exp": 1710086400,    <- expiration                  │
 * │   "roles": ["ROLE_USER"]  <- custom claims             │
 * │ }                                                       │
 * ├─────────────────────────────────────────────────────────┤
 * │ SIGNATURE                                               │
 * │ HMACSHA256(base64(header) + "." + base64(payload),     │
 * │            secret)                                      │
 * └─────────────────────────────────────────────────────────┘
 *
 * JWT is NOT encrypted by default — it's only SIGNED.
 * Anyone can decode header+payload. Never put sensitive data in JWT.
 * The SIGNATURE ensures the token wasn't tampered with.
 *
 * Types of Claims:
 * - Registered: iss, sub, aud, exp, nbf, iat, jti
 * - Public: custom, collision-resistant names
 * - Private: custom agreed-upon names between parties
 */
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration:86400000}") // 24 hours default
    private long jwtExpirationMs;

    @Value("${jwt.refresh-expiration:604800000}") // 7 days default
    private long refreshExpirationMs;

    // Extract username (subject) from token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                   .verifyWith(getSigningKey())
                   .build()
                   .parseSignedClaims(token)
                   .getPayload();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();
        // Add custom claims (authorities as roles list)
        extraClaims.put("roles", userDetails.getAuthorities()
            .stream()
            .map(a -> a.getAuthority())
            .toList());
        return buildToken(extraClaims, userDetails, jwtExpirationMs);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpirationMs);
    }

    private String buildToken(Map<String, Object> extraClaims,
                              UserDetails userDetails,
                              long expiration) {
        return Jwts.builder()
                   .claims(extraClaims)
                   .subject(userDetails.getUsername())
                   .issuedAt(new Date(System.currentTimeMillis()))
                   .expiration(new Date(System.currentTimeMillis() + expiration))
                   .signWith(getSigningKey())
                   .compact();
    }
}
