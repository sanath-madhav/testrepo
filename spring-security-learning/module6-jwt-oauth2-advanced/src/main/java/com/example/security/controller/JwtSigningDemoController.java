package com.example.security.controller;

import com.example.security.util.JwtSigningUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;

/**
 * Live demos for all three JWT signing algorithms.
 * Generates real signed tokens for comparison.
 */
@RestController
@RequestMapping("/api/jwt-demo")
@Tag(name = "JWT Signing Demo", description = "Live HS256, RS256, ES256 token generation and verification")
public class JwtSigningDemoController {

    private final JwtSigningUtil jwtSigningUtil;

    // In production: pre-generated and stored in a keystore/secrets manager
    // Here: generated fresh on startup for demo purposes
    private final KeyPair rsaKeyPair;
    private final KeyPair ecKeyPair;

    public JwtSigningDemoController(JwtSigningUtil jwtSigningUtil) {
        this.jwtSigningUtil = jwtSigningUtil;
        try {
            this.rsaKeyPair = jwtSigningUtil.generateRsaKeyPair();
            this.ecKeyPair = jwtSigningUtil.generateEcKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate key pairs", e);
        }
    }

    @GetMapping("/hs256")
    @Operation(summary = "Generate HS256 token — symmetric HMAC signing")
    public ResponseEntity<Map<String, Object>> generateHs256() {
        UserDetails user = buildTestUser();
        Map<String, Object> claims = Map.of("roles", List.of("ROLE_USER"), "demo", true);
        String token = jwtSigningUtil.generateHs256Token(user, claims);

        return ResponseEntity.ok(Map.of(
            "algorithm", "HS256",
            "type", "Symmetric (shared secret)",
            "token", token,
            "decoded", decodeJwtParts(token),
            "security", Map.of(
                "advantage", "Simple — one key to manage",
                "disadvantage", "All verifiers must share the secret — risk if any service is compromised",
                "keySize", "256-bit minimum for HS256",
                "useWhen", "Single-service or tightly controlled microservices"
            )
        ));
    }

    @GetMapping("/rs256")
    @Operation(summary = "Generate RS256 token — asymmetric RSA signing")
    public ResponseEntity<Map<String, Object>> generateRs256() {
        UserDetails user = buildTestUser();
        Map<String, Object> claims = Map.of("roles", List.of("ROLE_USER"), "alg_demo", "RS256");
        String token = jwtSigningUtil.generateRs256Token(user, claims, rsaKeyPair.getPrivate());

        Map<String, Object> jwk = jwtSigningUtil.buildRsaJwk(rsaKeyPair.getPublic(), "rsa-key-1");

        return ResponseEntity.ok(Map.of(
            "algorithm", "RS256",
            "type", "Asymmetric (RSA 2048-bit private/public key pair)",
            "token", token,
            "decoded", decodeJwtParts(token),
            "publicJwk", jwk,
            "security", Map.of(
                "advantage", "Resource servers only need public key — private key never leaves auth server",
                "publicKeyDistribution", "Via /.well-known/jwks.json endpoint (JWK Set)",
                "keyRotation", "Add new key pair to JWKS, sign new tokens with new 'kid', old tokens still verify",
                "keySize", "RSA-2048 minimum; RSA-4096 for high security",
                "signatureSize", "256 bytes for RSA-2048",
                "useWhen", "Multi-service / microservices where resource servers are separate"
            )
        ));
    }

    @GetMapping("/es256")
    @Operation(summary = "Generate ES256 token — asymmetric ECDSA signing")
    public ResponseEntity<Map<String, Object>> generateEs256() {
        UserDetails user = buildTestUser();
        Map<String, Object> claims = Map.of("roles", List.of("ROLE_USER"), "alg_demo", "ES256");
        String token = jwtSigningUtil.generateEs256Token(user, claims, ecKeyPair.getPrivate());

        Map<String, Object> jwk = jwtSigningUtil.buildEcJwk(ecKeyPair.getPublic(), "ec-key-1");

        return ResponseEntity.ok(Map.of(
            "algorithm", "ES256",
            "type", "Asymmetric (ECDSA P-256 / secp256r1)",
            "token", token,
            "decoded", decodeJwtParts(token),
            "publicJwk", jwk,
            "security", Map.of(
                "advantage", "Same asymmetric benefits as RS256 but smaller keys and signatures",
                "keySize", "256-bit EC key ≈ 3072-bit RSA security",
                "signatureSize", "64 bytes (vs 256 bytes for RSA-2048)",
                "performance", "Faster signing and verification, especially on mobile/IoT",
                "useWhen", "When token size matters (mobile, IoT) or when you need FIPS compliance with PS256"
            )
        ));
    }

    @GetMapping("/verify/rs256")
    @Operation(summary = "Verify an RS256 token using the public key")
    public ResponseEntity<Map<String, Object>> verifyRs256(@RequestParam String token) {
        try {
            var claims = jwtSigningUtil.validateRs256Token(token, rsaKeyPair.getPublic());
            return ResponseEntity.ok(Map.of(
                "valid", true,
                "subject", claims.getSubject(),
                "expiration", claims.getExpiration().toString(),
                "claims", claims
            ));
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(Map.of(
                "valid", false,
                "error", ex.getMessage()
            ));
        }
    }

    @GetMapping("/.well-known/jwks.json")
    @Operation(summary = "JWK Set endpoint — resource servers fetch public keys here")
    public ResponseEntity<Map<String, Object>> jwkSet() {
        return ResponseEntity.ok(Map.of(
            "keys", List.of(
                jwtSigningUtil.buildRsaJwk(rsaKeyPair.getPublic(), "rsa-key-1"),
                jwtSigningUtil.buildEcJwk(ecKeyPair.getPublic(), "ec-key-1")
            )
        ));
    }

    @GetMapping("/comparison")
    @Operation(summary = "Compare HS256 vs RS256 vs ES256")
    public ResponseEntity<Map<String, Object>> comparison() {
        return ResponseEntity.ok(Map.of(
            "HS256", Map.of("type","Symmetric","keyType","Shared HMAC secret","sigSize","32 bytes",
                "keySize","256+ bits","verify","Same secret","bestFor","Single server"),
            "RS256", Map.of("type","Asymmetric RSA","keyType","Private+Public key pair","sigSize","256 bytes",
                "keySize","2048 bits min","verify","Public key only","bestFor","Multi-service, JWKs"),
            "ES256", Map.of("type","Asymmetric ECDSA","keyType","Private+Public EC key pair","sigSize","64 bytes",
                "keySize","256 bits (≈3072 RSA)","verify","Public key only","bestFor","Mobile, IoT, size-sensitive"),
            "recommendation", "RS256 or ES256 for production APIs. ES256 preferred for modern systems."
        ));
    }

    private UserDetails buildTestUser() {
        return User.withUsername("demouser")
            .password("N/A")
            .authorities(new SimpleGrantedAuthority("ROLE_USER"))
            .build();
    }

    private Map<String, String> decodeJwtParts(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 3) return Map.of("error", "invalid token structure");
        return Map.of(
            "header_base64", parts[0],
            "payload_base64", parts[1],
            "signature_base64", parts[2],
            "hint", "Paste token at jwt.io to inspect (signature won't verify there — key not shared)"
        );
    }
}
