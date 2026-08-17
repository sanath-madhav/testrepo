package com.example.security.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * CONCEPT: JWT Signing Algorithms — Comparison and Implementation
 *
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     JWT SIGNATURE ALGORITHMS                                │
 * ├──────────┬──────────────┬────────────────┬───────────────────────────────┤
 * │ Algorithm│ Type         │ Key            │ Use Case                      │
 * ├──────────┼──────────────┼────────────────┼───────────────────────────────┤
 * │ HS256    │ HMAC-SHA256  │ Shared secret  │ Single-server, microservices  │
 * │ HS384    │ HMAC-SHA384  │ Shared secret  │ Stronger HMAC                 │
 * │ HS512    │ HMAC-SHA512  │ Shared secret  │ Strongest HMAC                │
 * ├──────────┼──────────────┼────────────────┼───────────────────────────────┤
 * │ RS256    │ RSA-SHA256   │ Private + Public│ Multi-service, public JWKs   │
 * │ RS384    │ RSA-SHA384   │ Private + Public│ Stronger RSA                 │
 * │ RS512    │ RSA-SHA512   │ Private + Public│ Strongest RSA                │
 * ├──────────┼──────────────┼────────────────┼───────────────────────────────┤
 * │ ES256    │ ECDSA-P256   │ Private + Public│ Compact, modern, IoT        │
 * │ ES384    │ ECDSA-P384   │ Private + Public│ Higher security              │
 * │ ES512    │ ECDSA-P521   │ Private + Public│ Highest security             │
 * ├──────────┼──────────────┼────────────────┼───────────────────────────────┤
 * │ PS256    │ RSASSA-PSS   │ Private + Public│ FIPS compliant              │
 * └──────────┴──────────────┴────────────────┴───────────────────────────────┘
 *
 * HS256 (Symmetric):
 * ┌──────────────────────────────────────────────────────────────┐
 * │ Auth Server ──sign(secret)──► JWT ──verify(same secret)──► │
 * │ Resource Server                                             │
 * │ PROBLEM: Resource server must hold the secret → risk if    │
 * │ compromised. All servers must share the same secret.       │
 * └──────────────────────────────────────────────────────────────┘
 *
 * RS256 (Asymmetric — RECOMMENDED for microservices):
 * ┌──────────────────────────────────────────────────────────────┐
 * │ Auth Server ──sign(PRIVATE key)──► JWT                      │
 * │ Resource Server ──verify(PUBLIC key only)                   │
 * │ BENEFIT: Resource servers only need the public key.        │
 * │ Private key stays only on Auth Server.                      │
 * │ Public key can be published via /.well-known/jwks.json      │
 * └──────────────────────────────────────────────────────────────┘
 *
 * ES256 (Asymmetric + Compact):
 * ┌──────────────────────────────────────────────────────────────┐
 * │ Same security model as RS256, but:                          │
 * │ • Smaller key sizes (256-bit vs 2048-bit RSA)              │
 * │ • Smaller signatures (64 bytes vs 256 bytes for RSA-2048)  │
 * │ • Faster on constrained devices                            │
 * │ • Mathematically different (Elliptic Curve Cryptography)   │
 * └──────────────────────────────────────────────────────────────┘
 */
@Component
public class JwtSigningUtil {

    @Value("${jwt.secret}")
    private String hmacSecret;

    @Value("${jwt.expiration:900000}") // 15 minutes for access tokens
    private long accessTokenExpiry;

    // ═══════════════════════════════════════════════════════════════
    // HS256 — Symmetric HMAC signing
    // ═══════════════════════════════════════════════════════════════

    /**
     * HS256: Both signing and verification use the SAME secret key.
     * The secret must be kept confidential on every service that verifies.
     * Minimum secret length: 256 bits (32 bytes) for HS256.
     */
    public String generateHs256Token(UserDetails userDetails, Map<String, Object> extraClaims) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(hmacSecret));

        return Jwts.builder()
            .header().add("alg", "HS256").add("typ", "JWT").and()
            .claims(extraClaims)
            .subject(userDetails.getUsername())
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + accessTokenExpiry))
            .signWith(key, Jwts.SIG.HS256)
            .compact();
    }

    public Claims validateHs256Token(String token) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(hmacSecret));
        return Jwts.parser().verifyWith(key).build()
                   .parseSignedClaims(token).getPayload();
    }

    // ═══════════════════════════════════════════════════════════════
    // RS256 — Asymmetric RSA signing (recommended for production)
    // ═══════════════════════════════════════════════════════════════

    /**
     * Generates an RSA key pair (in production: load from keystore).
     * RSA-2048 minimum recommended; RSA-4096 for high-security scenarios.
     *
     * In production:
     *   KeyStore ks = KeyStore.getInstance("JKS");
     *   ks.load(new FileInputStream("keystore.jks"), "password".toCharArray());
     *   PrivateKey privateKey = (PrivateKey) ks.getKey("mykey", "keypass".toCharArray());
     *   Certificate cert = ks.getCertificate("mykey");
     *   PublicKey publicKey = cert.getPublicKey();
     */
    public KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        return generator.generateKeyPair();
    }

    /**
     * RS256: Sign with PRIVATE key (only Auth Server has this).
     * Resource servers verify using the PUBLIC key (safe to distribute).
     */
    public String generateRs256Token(UserDetails userDetails,
                                      Map<String, Object> extraClaims,
                                      PrivateKey privateKey) {
        return Jwts.builder()
            .header()
                .add("alg", "RS256")
                .add("typ", "JWT")
                .add("kid", "rsa-key-1") // Key ID: used by clients to find right public key
            .and()
            .claims(extraClaims)
            .subject(userDetails.getUsername())
            .issuer("https://auth.example.com")
            .audience().add("https://api.example.com").and()
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + accessTokenExpiry))
            .signWith(privateKey, Jwts.SIG.RS256)
            .compact();
    }

    /**
     * RS256 verification: Only the PUBLIC key is needed.
     * The public key can be fetched from /.well-known/jwks.json.
     */
    public Claims validateRs256Token(String token, PublicKey publicKey) {
        return Jwts.parser()
                   .verifyWith(publicKey)
                   .build()
                   .parseSignedClaims(token)
                   .getPayload();
    }

    // ═══════════════════════════════════════════════════════════════
    // ES256 — Elliptic Curve asymmetric signing
    // ═══════════════════════════════════════════════════════════════

    /**
     * ES256 uses P-256 (secp256r1) elliptic curve.
     * Key advantages over RSA:
     * - 256-bit EC key ≈ 3072-bit RSA security level
     * - Signatures are 64 bytes (RS256 produces 256+ bytes)
     * - Faster verification, especially on constrained devices
     */
    public KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return generator.generateKeyPair();
    }

    public String generateEs256Token(UserDetails userDetails,
                                      Map<String, Object> extraClaims,
                                      PrivateKey ecPrivateKey) {
        return Jwts.builder()
            .header()
                .add("alg", "ES256")
                .add("kid", "ec-key-1")
            .and()
            .claims(extraClaims)
            .subject(userDetails.getUsername())
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + accessTokenExpiry))
            .signWith(ecPrivateKey, Jwts.SIG.ES256)
            .compact();
    }

    public Claims validateEs256Token(String token, PublicKey ecPublicKey) {
        return Jwts.parser()
                   .verifyWith(ecPublicKey)
                   .build()
                   .parseSignedClaims(token)
                   .getPayload();
    }

    // ═══════════════════════════════════════════════════════════════
    // JWK (JSON Web Key) — public key distribution format
    // ═══════════════════════════════════════════════════════════════

    /**
     * JWK Set endpoint (/.well-known/jwks.json) lets resource servers
     * fetch public keys automatically without manual configuration.
     *
     * Example JWK Set response:
     * {
     *   "keys": [
     *     {
     *       "kty": "RSA",         <- key type
     *       "kid": "rsa-key-1",   <- key ID (matches "kid" in JWT header)
     *       "use": "sig",         <- key usage: signature
     *       "alg": "RS256",
     *       "n": "...",           <- RSA modulus (Base64URL)
     *       "e": "AQAB"           <- RSA exponent (always AQAB = 65537)
     *     }
     *   ]
     * }
     *
     * Resource Server flow with JWKs:
     * 1. Receive JWT with "kid": "rsa-key-1" in header
     * 2. Fetch /.well-known/jwks.json (or use cached version)
     * 3. Find key where "kid" == "rsa-key-1"
     * 4. Use that public key to verify the signature
     * 5. Cache the JWK Set (refresh on cache miss for unknown kid)
     *
     * This enables KEY ROTATION:
     * - Generate new key pair
     * - Add new public key to JWKS with new "kid"
     * - Start signing new tokens with new private key + new "kid"
     * - Old tokens still verify using old public key (still in JWKS)
     * - Remove old public key after all old tokens expire
     */
    public Map<String, Object> buildRsaJwk(PublicKey publicKey, String keyId) {
        java.security.interfaces.RSAPublicKey rsaKey =
            (java.security.interfaces.RSAPublicKey) publicKey;

        return Map.of(
            "kty", "RSA",
            "kid", keyId,
            "use", "sig",
            "alg", "RS256",
            "n", java.util.Base64.getUrlEncoder().withoutPadding()
                     .encodeToString(rsaKey.getModulus().toByteArray()),
            "e", java.util.Base64.getUrlEncoder().withoutPadding()
                     .encodeToString(rsaKey.getPublicExponent().toByteArray())
        );
    }

    public Map<String, Object> buildEcJwk(PublicKey publicKey, String keyId) {
        java.security.interfaces.ECPublicKey ecKey =
            (java.security.interfaces.ECPublicKey) publicKey;

        return Map.of(
            "kty", "EC",
            "kid", keyId,
            "use", "sig",
            "alg", "ES256",
            "crv", "P-256",
            "x", java.util.Base64.getUrlEncoder().withoutPadding()
                     .encodeToString(ecKey.getW().getAffineX().toByteArray()),
            "y", java.util.Base64.getUrlEncoder().withoutPadding()
                     .encodeToString(ecKey.getW().getAffineY().toByteArray())
        );
    }
}
