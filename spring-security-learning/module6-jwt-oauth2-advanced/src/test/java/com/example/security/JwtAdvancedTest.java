package com.example.security;

import com.example.security.service.RefreshTokenService;
import com.example.security.service.RefreshTokenService.RefreshTokenException;
import com.example.security.util.AccessTokenUtil;
import com.example.security.util.JwtSigningUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class JwtAdvancedTest {

    @Autowired MockMvc mockMvc;
    @Autowired AccessTokenUtil accessTokenUtil;
    @Autowired RefreshTokenService refreshTokenService;
    @Autowired UserDetailsService userDetailsService;
    @Autowired JwtSigningUtil jwtSigningUtil;

    // ─── Login / Access Token Tests ───────────────────────────────────────────

    @Test
    void loginWithValidCredentialsReturnsTokens() throws Exception {
        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"username":"alice","password":"pass123"}
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").exists())
            .andExpect(jsonPath("$.refreshToken").exists())
            .andExpect(jsonPath("$.tokenType").value("Bearer"))
            .andExpect(jsonPath("$.accessExpiresIn").value("900 seconds"));
    }

    @Test
    void loginWithInvalidCredentialsReturns401() throws Exception {
        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"username":"alice","password":"wrongpassword"}
                    """))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("Invalid credentials"));
    }

    @Test
    void protectedEndpointWithoutTokenReturns401() throws Exception {
        mockMvc.perform(get("/api/some-protected"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointWithValidAccessTokenSucceeds() throws Exception {
        UserDetails alice = userDetailsService.loadUserByUsername("alice");
        String token = accessTokenUtil.generateAccessToken(alice);

        mockMvc.perform(get("/api/jwt-demo/hs256")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.algorithm").value("HS256"))
            .andExpect(jsonPath("$.token").exists());
    }

    // ─── Refresh Token Rotation Tests ─────────────────────────────────────────

    @Test
    void refreshTokenRotationIssuesNewPairAndInvalidatesOld() throws Exception {
        // Step 1: login to get initial refresh token
        String loginBody = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"username":"alice","password":"pass123"}
                    """))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        String refreshToken = extractField(loginBody, "refreshToken");

        // Step 2: use refresh token to get new pair
        String refreshBody = mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").exists())
            .andExpect(jsonPath("$.refreshToken").exists())
            .andReturn().getResponse().getContentAsString();

        String newRefreshToken = extractField(refreshBody, "refreshToken");
        assertThat(newRefreshToken).isNotEqualTo(refreshToken);

        // Step 3: reusing old refresh token must fail (rotation invalidated it)
        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshTokenTheftDetectionRevokesFamily() {
        // Simulate theft: get a token, rotate it, then try to use the original again
        UserDetails alice = userDetailsService.loadUserByUsername("alice");
        var initialToken = refreshTokenService.createRefreshToken(alice);
        String tokenValue = initialToken.getToken();

        // Legitimate rotation by the real client
        refreshTokenService.rotateRefreshToken(tokenValue);

        // Attacker tries to use the stolen original token — should trigger theft detection
        assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken(tokenValue))
            .isInstanceOf(RefreshTokenException.class)
            .hasMessageContaining("Refresh token reuse detected");
    }

    @Test
    void logoutRevokesRefreshTokenFamily() throws Exception {
        // Login
        String loginBody = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"username":"bob","password":"pass123"}
                    """))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        String refreshToken = extractField(loginBody, "refreshToken");

        // Logout
        mockMvc.perform(post("/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").exists());

        // Refresh after logout must fail
        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
            .andExpect(status().isUnauthorized());
    }

    // ─── JWT Signing Algorithm Tests ──────────────────────────────────────────

    @Test
    void hs256DemoEndpointReturnsValidToken() throws Exception {
        mockMvc.perform(get("/api/jwt-demo/hs256"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.algorithm").value("HS256"))
            .andExpect(jsonPath("$.type").value("Symmetric (shared secret)"))
            .andExpect(jsonPath("$.token").exists())
            .andExpect(jsonPath("$.security.advantage").exists());
    }

    @Test
    void rs256DemoEndpointReturnsTokenAndJwk() throws Exception {
        mockMvc.perform(get("/api/jwt-demo/rs256"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.algorithm").value("RS256"))
            .andExpect(jsonPath("$.token").exists())
            .andExpect(jsonPath("$.publicJwk.kty").value("RSA"))
            .andExpect(jsonPath("$.publicJwk.alg").value("RS256"))
            .andExpect(jsonPath("$.publicJwk.kid").value("rsa-key-1"));
    }

    @Test
    void es256DemoEndpointReturnsTokenAndEcJwk() throws Exception {
        mockMvc.perform(get("/api/jwt-demo/es256"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.algorithm").value("ES256"))
            .andExpect(jsonPath("$.token").exists())
            .andExpect(jsonPath("$.publicJwk.kty").value("EC"))
            .andExpect(jsonPath("$.publicJwk.crv").value("P-256"));
    }

    @Test
    void jwksEndpointExposesBothPublicKeys() throws Exception {
        mockMvc.perform(get("/api/jwt-demo/.well-known/jwks.json"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keys").isArray())
            .andExpect(jsonPath("$.keys.length()").value(2));
    }

    @Test
    void rs256TokenVerifyEndpointValidatesToken() throws Exception {
        // Get an RS256 token first
        String body = mockMvc.perform(get("/api/jwt-demo/rs256"))
            .andReturn().getResponse().getContentAsString();
        String token = extractField(body, "token");

        mockMvc.perform(get("/api/jwt-demo/verify/rs256")
                .param("token", token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.valid").value(true))
            .andExpect(jsonPath("$.subject").value("demouser"));
    }

    @Test
    void rs256TokenVerifyEndpointRejectsTamperedToken() throws Exception {
        mockMvc.perform(get("/api/jwt-demo/verify/rs256")
                .param("token", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.invalidsig"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.valid").value(false));
    }

    @Test
    void algorithmComparisonEndpointCoversAllThree() throws Exception {
        mockMvc.perform(get("/api/jwt-demo/comparison"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.HS256").exists())
            .andExpect(jsonPath("$.RS256").exists())
            .andExpect(jsonPath("$.ES256").exists())
            .andExpect(jsonPath("$.recommendation").exists());
    }

    // ─── OAuth2 Grant Type Guide Tests ────────────────────────────────────────

    @Test
    void authorizationCodePkceGuideReturnsDetails() throws Exception {
        mockMvc.perform(get("/api/oauth2-guide/authorization-code-pkce"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.grantType").value("authorization_code"))
            .andExpect(jsonPath("$.pkceRequired").exists())
            .andExpect(jsonPath("$.step1_generatePkce").exists());
    }

    @Test
    void clientCredentialsGuideReturnsDetails() throws Exception {
        mockMvc.perform(get("/api/oauth2-guide/client-credentials"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.grantType").value("client_credentials"))
            .andExpect(jsonPath("$.useCase").exists());
    }

    @Test
    void deviceCodeGuideReturnsDetails() throws Exception {
        mockMvc.perform(get("/api/oauth2-guide/device-code"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.grantType").value("urn:ietf:params:oauth:grant-type:device_code"))
            .andExpect(jsonPath("$.step1_deviceRequest").exists());
    }

    @Test
    void deprecatedGrantsGuideExplainsRemoval() throws Exception {
        mockMvc.perform(get("/api/oauth2-guide/deprecated-grants"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.implicit").exists())
            .andExpect(jsonPath("$.resourceOwnerPasswordCredentials").exists());
    }

    @Test
    void allGrantsSummaryListsAllTypes() throws Exception {
        mockMvc.perform(get("/api/oauth2-guide/all-grants-summary"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.currentGrants").exists())
            .andExpect(jsonPath("$.deprecated").exists())
            .andExpect(jsonPath("$.oauth21Changes").isArray());
    }

    // ─── Unit Tests: JwtSigningUtil ───────────────────────────────────────────

    @Test
    void hs256TokenRoundTrip() throws Exception {
        UserDetails user = userDetailsService.loadUserByUsername("alice");
        String token = jwtSigningUtil.generateHs256Token(user, java.util.Map.of("role", "ROLE_USER"));
        var claims = jwtSigningUtil.validateHs256Token(token);
        assertThat(claims.getSubject()).isEqualTo("alice");
    }

    @Test
    void rs256TokenRoundTrip() throws Exception {
        UserDetails user = userDetailsService.loadUserByUsername("alice");
        java.security.KeyPair kp = jwtSigningUtil.generateRsaKeyPair();
        String token = jwtSigningUtil.generateRs256Token(user, java.util.Map.of(), kp.getPrivate());
        var claims = jwtSigningUtil.validateRs256Token(token, kp.getPublic());
        assertThat(claims.getSubject()).isEqualTo("alice");
    }

    @Test
    void es256TokenRoundTrip() throws Exception {
        UserDetails user = userDetailsService.loadUserByUsername("bob");
        java.security.KeyPair kp = jwtSigningUtil.generateEcKeyPair();
        String token = jwtSigningUtil.generateEs256Token(user, java.util.Map.of(), kp.getPrivate());
        var claims = jwtSigningUtil.validateEs256Token(token, kp.getPublic());
        assertThat(claims.getSubject()).isEqualTo("bob");
    }

    // ─── Helper ───────────────────────────────────────────────────────────────

    private String extractField(String json, String field) {
        // Minimal JSON field extractor for test use — not for production
        int idx = json.indexOf("\"" + field + "\":\"");
        if (idx == -1) return "";
        int start = idx + field.length() + 4;
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }
}
