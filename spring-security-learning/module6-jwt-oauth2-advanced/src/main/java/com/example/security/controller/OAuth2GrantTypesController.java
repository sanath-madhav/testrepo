package com.example.security.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * CONCEPT: OAuth2 Grant Types — Complete Reference
 *
 * OAuth2 defines several "grant types" — methods by which a client can obtain
 * an access token. The grant type determines WHO authorizes the request and HOW.
 *
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │              OAUTH2 GRANT TYPE DECISION TREE                                │
 * │                                                                             │
 * │  Is there a user (resource owner) involved?                                │
 * │  YES ──┬── Is the client a web app on a server?                            │
 * │         │   YES → Authorization Code Flow (+ PKCE if public client)        │
 * │         │                                                                   │
 * │         └── Is the client a device without a browser?                      │
 * │             YES → Device Authorization Grant                               │
 * │                                                                             │
 * │  NO  → Client Credentials (machine-to-machine)                            │
 * │                                                                             │
 * │  DEPRECATED (avoid):                                                        │
 * │  • Implicit Grant (replaced by Auth Code + PKCE)                          │
 * │  • Resource Owner Password Credentials (too much trust in client)         │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * Spring Authorization Server supports:
 * - authorization_code (+ PKCE)
 * - client_credentials
 * - refresh_token
 * - device_code
 * - token_exchange (RFC 8693)
 *
 * This controller documents each grant type with real HTTP request examples.
 */
@RestController
@RequestMapping("/api/oauth2-guide")
@Tag(name = "OAuth2 Grant Types Reference", description = "Documentation and flows for all OAuth2 grant types")
public class OAuth2GrantTypesController {

    /**
     * GRANT TYPE 1: Authorization Code + PKCE
     *
     * Who uses it: Web apps (server-side), Single Page Apps (SPA), Mobile apps
     * User involved: YES
     * Security level: HIGHEST
     *
     * PKCE (Proof Key for Code Exchange) — RFC 7636:
     * Required for public clients (SPA, mobile) that cannot safely store a client_secret.
     *
     * PKCE Flow:
     * ┌─────────────────────────────────────────────────────────────────┐
     * │ 1. Client generates:                                             │
     * │    code_verifier = random 43-128 char string (high entropy)    │
     * │    code_challenge = BASE64URL(SHA256(code_verifier))           │
     * │                                                                 │
     * │ 2. Client sends authorization request WITH code_challenge:      │
     * │    GET /oauth2/authorize                                         │
     * │      ?response_type=code                                        │
     * │      &client_id=my-app                                         │
     * │      &redirect_uri=https://app.com/callback                    │
     * │      &scope=openid email profile                               │
     * │      &state=csrf_random_value                                  │
     * │      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw │
     * │      &code_challenge_method=S256                               │
     * │                                                                 │
     * │ 3. Auth server stores code_challenge                           │
     * │ 4. User authenticates, Auth server returns code to redirect_uri │
     * │                                                                 │
     * │ 5. Client exchanges code + code_VERIFIER for tokens:           │
     * │    POST /oauth2/token                                           │
     * │    grant_type=authorization_code                               │
     * │    &code=the_code                                              │
     * │    &redirect_uri=https://app.com/callback                     │
     * │    &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk │
     * │                                                                 │
     * │ 6. Auth server verifies: SHA256(code_verifier) == code_challenge│
     * │    (Only the original requester knows the verifier!)           │
     * │    Returns: {access_token, refresh_token, id_token}            │
     * │                                                                 │
     * │ WHY PKCE PREVENTS AUTHORIZATION CODE INTERCEPTION:             │
     * │ Without PKCE: Attacker intercepts the code → gets tokens       │
     * │ With PKCE: Attacker gets the code but NOT the code_verifier   │
     * │           → Auth server rejects token exchange without verifier │
     * └─────────────────────────────────────────────────────────────────┘
     */
    @GetMapping("/authorization-code-pkce")
    @Operation(summary = "Guide: Authorization Code + PKCE flow details")
    public ResponseEntity<Map<String, Object>> authCodePkceGuide() {
        return ResponseEntity.ok(Map.of(
            "grantType", "authorization_code",
            "pkceRequired", "Yes, for public clients (SPA, mobile)",
            "step1_generatePkce", Map.of(
                "code_verifier", "Generate 32-96 random bytes, Base64URL encode",
                "code_challenge", "BASE64URL(SHA256(code_verifier))",
                "code_challenge_method", "S256"
            ),
            "step2_authorizeUrl", Map.of(
                "url", "GET /oauth2/authorize",
                "params", Map.of(
                    "response_type", "code",
                    "client_id", "your-client-id",
                    "redirect_uri", "https://yourapp.com/callback",
                    "scope", "openid email profile",
                    "state", "random-csrf-token",
                    "code_challenge", "computed-challenge",
                    "code_challenge_method", "S256"
                )
            ),
            "step3_tokenExchange", Map.of(
                "url", "POST /oauth2/token",
                "body", Map.of(
                    "grant_type", "authorization_code",
                    "code", "received-authorization-code",
                    "redirect_uri", "https://yourapp.com/callback",
                    "client_id", "your-client-id",
                    "code_verifier", "original-code-verifier"
                )
            ),
            "response", Map.of(
                "access_token", "...", "refresh_token", "...",
                "id_token", "...(OIDC)", "token_type", "Bearer", "expires_in", 900
            )
        ));
    }

    /**
     * GRANT TYPE 2: Client Credentials
     *
     * Who uses it: Machine-to-machine (no user involved)
     * User involved: NO
     * Examples: Microservice calling another microservice, cron jobs, background workers
     *
     * Flow:
     * ┌──────────────────────────────────────────────────────────────┐
     * │ Service A (client) → Auth Server:                            │
     * │ POST /oauth2/token                                           │
     * │   grant_type=client_credentials                             │
     * │   &client_id=service-a                                      │
     * │   &client_secret=secret123                                  │
     * │   &scope=read:orders write:inventory                        │
     * │                                                              │
     * │ Auth Server validates credentials, returns:                  │
     * │ { access_token: "...", token_type: "Bearer", expires_in: 3600 } │
     * │ NOTE: No refresh_token (client can just request a new one)  │
     * │                                                              │
     * │ Service A uses token to call Service B:                     │
     * │ GET /api/orders                                              │
     * │ Authorization: Bearer <access_token>                        │
     * └──────────────────────────────────────────────────────────────┘
     *
     * Spring Security OAuth2 Resource Server configuration for M2M:
     * The receiving service (Resource Server) validates the JWT using JWKs.
     */
    @GetMapping("/client-credentials")
    @Operation(summary = "Guide: Client Credentials flow (machine-to-machine)")
    public ResponseEntity<Map<String, Object>> clientCredentialsGuide() {
        return ResponseEntity.ok(Map.of(
            "grantType", "client_credentials",
            "useCase", "Machine-to-machine, no user interaction",
            "examples", new String[]{
                "Microservice-to-microservice calls",
                "Background jobs / cron tasks",
                "API gateway to backend service",
                "CI/CD pipeline calling deployment API"
            },
            "tokenRequest", Map.of(
                "method", "POST",
                "url", "/oauth2/token",
                "headers", "Authorization: Basic BASE64(client_id:client_secret)",
                "body", Map.of("grant_type", "client_credentials",
                               "scope", "read:data write:data")
            ),
            "curlExample", "curl -X POST /oauth2/token \\\n" +
                "  -H 'Authorization: Basic Y2xpZW50OnNlY3JldA==' \\\n" +
                "  -d 'grant_type=client_credentials&scope=read:data'",
            "noRefreshToken", "True — client can just re-authenticate when token expires",
            "springConfig", Map.of(
                "resourceServer", "@EnableWebSecurity + oauth2ResourceServer(jwt→)",
                "jwksUri", "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=..."
            )
        ));
    }

    /**
     * GRANT TYPE 3: Device Authorization Grant (RFC 8628)
     *
     * Who uses it: Smart TVs, CLIs, IoT devices, gaming consoles
     * User involved: YES (on a different device)
     * Problem solved: Device has no browser / limited input
     *
     * Flow:
     * ┌──────────────────────────────────────────────────────────────┐
     * │ 1. Device requests a user code from Auth Server:             │
     * │    POST /oauth2/device_authorization                         │
     * │    client_id=smart-tv-app&scope=openid profile              │
     * │                                                              │
     * │ 2. Auth Server returns:                                      │
     * │    { device_code: "Ag_EE...GJA",                           │
     * │      user_code: "WDJB-MJHT",          ← show to user        │
     * │      verification_uri: "https://example.com/activate",     │
     * │      verification_uri_complete: "...?user_code=WDJB-MJHT", │
     * │      expires_in: 1800,                                      │
     * │      interval: 5 }                                          │
     * │                                                              │
     * │ 3. Device displays: "Visit https://example.com/activate     │
     * │    and enter code: WDJB-MJHT"                              │
     * │    (or shows a QR code of verification_uri_complete)        │
     * │                                                              │
     * │ 4. User opens browser on PHONE/PC → enters code → approves │
     * │                                                              │
     * │ 5. Device polls Auth Server every `interval` seconds:       │
     * │    POST /oauth2/token                                        │
     * │    grant_type=urn:ietf:params:oauth:grant-type:device_code │
     * │    &device_code=Ag_EE...GJA                                │
     * │    &client_id=smart-tv-app                                  │
     * │    Until: authorization_pending → wait; access_denied →    │
     * │    show error; success → use tokens                         │
     * └──────────────────────────────────────────────────────────────┘
     */
    @GetMapping("/device-code")
    @Operation(summary = "Guide: Device Authorization Grant flow")
    public ResponseEntity<Map<String, Object>> deviceCodeGuide() {
        return ResponseEntity.ok(Map.of(
            "grantType", "urn:ietf:params:oauth:grant-type:device_code",
            "useCase", "Smart TVs, CLIs, IoT, gaming consoles — no browser",
            "step1_deviceRequest", Map.of(
                "url", "POST /oauth2/device_authorization",
                "body", Map.of("client_id", "smart-tv", "scope", "openid profile")
            ),
            "step2_serverResponse", Map.of(
                "device_code", "Ag_EE...GJA  (device uses this to poll)",
                "user_code", "WDJB-MJHT  (show this to user)",
                "verification_uri", "https://example.com/activate",
                "expires_in", 1800,
                "interval", 5
            ),
            "step3_userAction", "User visits URL on phone/PC, enters user_code, approves",
            "step4_devicePolls", Map.of(
                "url", "POST /oauth2/token",
                "body", Map.of(
                    "grant_type", "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code", "Ag_EE...GJA",
                    "client_id", "smart-tv"
                ),
                "possibleErrors", new String[]{
                    "authorization_pending — user hasn't approved yet, keep polling",
                    "slow_down — increase polling interval by 5s",
                    "access_denied — user denied, stop polling",
                    "expired_token — device_code expired, restart flow"
                }
            ),
            "step5_success", Map.of("access_token", "...", "refresh_token", "...",
                                     "id_token", "...")
        ));
    }

    /**
     * GRANT TYPE 4: Refresh Token Grant
     *
     * Not a standalone flow — used to get new access tokens.
     * Already implemented in TokenController with ROTATION.
     */
    @GetMapping("/refresh-token")
    @Operation(summary = "Guide: Refresh Token grant (see /auth/refresh for implementation)")
    public ResponseEntity<Map<String, Object>> refreshTokenGuide() {
        return ResponseEntity.ok(Map.of(
            "grantType", "refresh_token",
            "purpose", "Get new access token without re-authenticating the user",
            "tokenRequest", Map.of(
                "url", "POST /oauth2/token",
                "body", Map.of(
                    "grant_type", "refresh_token",
                    "refresh_token", "the-refresh-token",
                    "client_id", "your-client",
                    "scope", "openid profile  (optional, must be subset of original)"
                )
            ),
            "securityBestPractices", new String[]{
                "Use refresh token ROTATION — invalidate old token on each use",
                "Store refresh token in HttpOnly cookie (XSS-safe) or secure storage",
                "Never store in localStorage (vulnerable to XSS)",
                "Implement refresh token families for theft detection",
                "Set absolute expiry (not just sliding) — force re-login eventually",
                "Use opaque (random) refresh tokens, NOT JWTs — they can be revoked"
            },
            "seeImplementation", "POST /auth/refresh in this module"
        ));
    }

    /**
     * DEPRECATED GRANT TYPES — understand why they were removed
     */
    @GetMapping("/deprecated-grants")
    @Operation(summary = "Guide: Deprecated grant types (Implicit, ROPC) — why they were removed")
    public ResponseEntity<Map<String, Object>> deprecatedGrantsGuide() {
        return ResponseEntity.ok(Map.of(
            "implicit", Map.of(
                "status", "REMOVED in OAuth 2.1",
                "whatItDid", "Returned access_token directly in redirect URL fragment #access_token=...",
                "problem1", "Token exposed in browser history, server logs, Referer headers",
                "problem2", "No client authentication possible",
                "problem3", "Vulnerable to token injection attacks",
                "replacement", "Authorization Code + PKCE for SPAs and mobile apps"
            ),
            "resourceOwnerPasswordCredentials", Map.of(
                "status", "REMOVED in OAuth 2.1",
                "whatItDid", "Client collected username/password directly, sent to auth server",
                "problem1", "Client must handle user credentials — defeats purpose of OAuth2 (delegation)",
                "problem2", "Cannot support MFA, captcha, federated SSO",
                "problem3", "Client could log or steal credentials",
                "problem4", "Creates tight coupling between client and auth server",
                "legitimateUseCase", "Migration period only — when you control both client and server",
                "replacement", "Authorization Code + PKCE for native apps"
            )
        ));
    }

    @GetMapping("/all-grants-summary")
    @Operation(summary = "Quick reference: all OAuth2 grant types")
    public ResponseEntity<Map<String, Object>> summary() {
        return ResponseEntity.ok(Map.of(
            "currentGrants", Map.of(
                "authorization_code+PKCE", "Web apps, SPAs, mobile — user present",
                "client_credentials", "Machine-to-machine — no user",
                "device_code", "TV/CLI/IoT — user on different device",
                "refresh_token", "Renew access tokens without re-login"
            ),
            "deprecated", Map.of(
                "implicit", "Removed — use auth_code+PKCE instead",
                "password", "Removed — anti-pattern, client handles credentials"
            ),
            "oauth21Changes", new String[]{
                "PKCE required for all public clients",
                "Implicit grant removed",
                "Resource Owner Password Credentials removed",
                "Refresh token rotation required",
                "Exact redirect URI matching required (no wildcards)"
            }
        ));
    }
}
