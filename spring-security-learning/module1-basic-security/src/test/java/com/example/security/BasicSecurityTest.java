package com.example.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Spring Security Test Utilities:
 * - @WithMockUser: bypasses authentication, injects a mock user into SecurityContext
 * - @WithUserDetails: loads real UserDetails from UserDetailsService
 * - formLogin(): simulates form-based login POST request
 * - SecurityMockMvcResultMatchers: specialized matchers for security state
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("inmemory")
class BasicSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Unauthenticated access to protected resource redirects to login")
    void unauthenticatedAccessRedirects() throws Exception {
        mockMvc.perform(get("/dashboard"))
               .andExpect(status().is3xxRedirection())
               .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    @DisplayName("Public endpoints accessible without authentication")
    void publicEndpointAccessible() throws Exception {
        mockMvc.perform(get("/home"))
               .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Valid login succeeds")
    void validLoginSucceeds() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("password"))
               .andExpect(authenticated());
    }

    @Test
    @DisplayName("Invalid login fails")
    void invalidLoginFails() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("wrongpassword"))
               .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Authenticated user can access dashboard")
    @WithMockUser(username = "user", roles = {"USER"})
    void authenticatedUserAccessesDashboard() throws Exception {
        mockMvc.perform(get("/dashboard"))
               .andExpect(status().isOk());
    }

    @Test
    @DisplayName("USER role cannot access admin endpoint")
    @WithMockUser(username = "user", roles = {"USER"})
    void userCannotAccessAdmin() throws Exception {
        mockMvc.perform(get("/admin"))
               .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ADMIN role can access admin endpoint")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void adminCanAccessAdmin() throws Exception {
        mockMvc.perform(get("/admin"))
               .andExpect(status().isOk());
    }
}
