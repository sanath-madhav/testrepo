package com.example.security;

import com.example.security.service.BruteForceProtectionService;
import com.example.security.service.PasswordPolicyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AdvancedSecurityTest {

    @Autowired MockMvc mockMvc;
    @Autowired BruteForceProtectionService bruteForceProtectionService;
    @Autowired PasswordPolicyService passwordPolicyService;

    // ─── Authentication & JWT Tests ───────────────────────────────────────────

    @Test
    void loginWithValidCredentialsReturnsJwt() throws Exception {
        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"username":"alice","password":"Alice@1234"}
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").exists())
            .andExpect(jsonPath("$.tokenType").value("Bearer"))
            .andExpect(jsonPath("$.username").value("alice"));
    }

    @Test
    void loginWithWrongPasswordReturns401() throws Exception {
        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"username":"alice","password":"wrongpassword"}
                    """))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("Invalid credentials"));
    }

    @Test
    void unauthenticatedRequestReturns401() throws Exception {
        mockMvc.perform(get("/api/me"))
            .andExpect(status().isUnauthorized());
    }

    // ─── Brute Force Protection Tests ─────────────────────────────────────────

    @Test
    void bruteForceProtectionLocksAccountAfterMaxAttempts() throws Exception {
        // Use admin for this brute force test to avoid locking alice (used in other tests)
        String testUser = "admin";

        // Ensure user starts unlocked
        bruteForceProtectionService.recordSuccessfulLogin(testUser);

        // Fire 5 failures
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"username\":\"admin\",\"password\":\"wrongpassword\"}"));
        }

        try {
            // Next attempt should get locked response (even with correct password)
            mockMvc.perform(post("/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {"username":"admin","password":"Admin@1234"}
                        """))
                .andExpect(status().is(423)); // 423 Locked
        } finally {
            // Cleanup: unlock admin so other tests are not affected
            bruteForceProtectionService.recordSuccessfulLogin(testUser);
        }
    }

    @Test
    void bruteForceServiceTracksAttemptsCorrectly() {
        // Use manager user so we don't interfere with alice's state from other tests
        bruteForceProtectionService.recordSuccessfulLogin("manager"); // reset first
        assertThat(bruteForceProtectionService.isLocked("manager")).isFalse();
        assertThat(bruteForceProtectionService.getRemainingAttempts("manager")).isEqualTo(5);

        bruteForceProtectionService.recordFailedAttempt("manager");
        assertThat(bruteForceProtectionService.getRemainingAttempts("manager")).isEqualTo(4);

        bruteForceProtectionService.recordSuccessfulLogin("manager");
        assertThat(bruteForceProtectionService.getRemainingAttempts("manager")).isEqualTo(5);
    }

    // ─── Role Hierarchy Tests ──────────────────────────────────────────────────

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void adminCanAccessManagerEndpointViaRoleHierarchy() throws Exception {
        mockMvc.perform(get("/api/manager/dashboard"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.dashboard").value("Manager Dashboard"));
    }

    @Test
    @WithMockUser(username = "manager", roles = {"MANAGER"})
    void managerCanAccessUserEndpointViaRoleHierarchy() throws Exception {
        mockMvc.perform(get("/api/user/data"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data").value("User-level data"));
    }

    @Test
    @WithMockUser(username = "alice", roles = {"USER"})
    void userCannotAccessAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "manager", roles = {"MANAGER"})
    void managerCannotAccessAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void adminCanAccessAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
            .andExpect(status().isOk());
    }

    // ─── @AuthenticationPrincipal Tests ───────────────────────────────────────

    @Test
    @WithMockUser(username = "alice", roles = {"USER"})
    void meEndpointReturnsCurrentUserDetails() throws Exception {
        mockMvc.perform(get("/api/me"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("alice"))
            .andExpect(jsonPath("$.roles").isArray());
    }

    // ─── Security Headers Tests ────────────────────────────────────────────────

    @Test
    @WithMockUser
    void securityHeadersArePresentOnResponses() throws Exception {
        mockMvc.perform(get("/api/me"))
            .andExpect(header().exists("X-Content-Type-Options"))
            .andExpect(header().string("X-Content-Type-Options", "nosniff"))
            .andExpect(header().exists("X-Frame-Options"));
    }

    // ─── Password Policy Tests ─────────────────────────────────────────────────

    @Test
    void passwordPolicyRejectsWeakPasswords() {
        var result = passwordPolicyService.validate("pass", "alice");
        assertThat(result.valid()).isFalse();
        assertThat(result.violations()).isNotEmpty();
    }

    @Test
    void passwordPolicyRejectsCommonPassword() {
        var result = passwordPolicyService.validate("password123", "alice");
        assertThat(result.valid()).isFalse();
    }

    @Test
    void passwordPolicyRejectsPasswordContainingUsername() {
        var result = passwordPolicyService.validate("Alice@1234", "Alice");
        assertThat(result.valid()).isFalse();
        assertThat(result.violations()).anyMatch(v -> v.contains("username"));
    }

    @Test
    void passwordPolicyAcceptsStrongPassword() {
        var result = passwordPolicyService.validate("Xk9#mQpR7@wL", "alice");
        assertThat(result.valid()).isTrue();
        assertThat(result.violations()).isEmpty();
    }

    @Test
    void passwordStrengthScoreIncreasesWithComplexity() {
        assertThat(passwordPolicyService.calculateStrength("weak")).isLessThan(3);
        assertThat(passwordPolicyService.calculateStrength("Str0ng@Pass!word")).isGreaterThan(3);
    }

    @Test
    void publicPasswordCheckEndpointWorks() throws Exception {
        mockMvc.perform(post("/api/public/password-check")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"password":"weak","username":"alice"}
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.valid").value(false))
            .andExpect(jsonPath("$.violations").isArray())
            .andExpect(jsonPath("$.strength").isNumber())
            .andExpect(jsonPath("$.strengthLabel").exists());
    }

    // ─── Security Concepts Guides ──────────────────────────────────────────────

    @Test
    void roleHierarchyGuideEndpointIsPublic() throws Exception {
        mockMvc.perform(get("/api/public/concepts/role-hierarchy"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.concept").value("Role Hierarchy"));
    }

    @Test
    void securityHeadersGuideEndpointIsPublic() throws Exception {
        mockMvc.perform(get("/api/public/concepts/security-headers"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.headers").isArray());
    }

    @Test
    void bruteForceGuideEndpointIsPublic() throws Exception {
        mockMvc.perform(get("/api/public/concepts/brute-force-protection"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.concept").value("Brute Force Protection"));
    }

    @Test
    void aclGuideEndpointIsPublic() throws Exception {
        mockMvc.perform(get("/api/public/concepts/acl"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.concept").value("ACL — Access Control Lists"));
    }

    // ─── Audit Log Tests ───────────────────────────────────────────────────────

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void adminCanAccessAuditLog() throws Exception {
        mockMvc.perform(get("/api/audit/recent"))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "alice", roles = {"USER"})
    void nonAdminCannotAccessAuditLog() throws Exception {
        mockMvc.perform(get("/api/audit/recent"))
            .andExpect(status().isForbidden());
    }
}
