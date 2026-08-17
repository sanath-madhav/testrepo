package com.example.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Testing OAuth2: Use @WithMockUser or @WithOAuth2Login to bypass actual OAuth2 flow.
 * In real integration tests, mock the OAuth2 provider using WireMock.
 */
@SpringBootTest
@AutoConfigureMockMvc
class OAuth2SecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Unauthenticated access to dashboard redirects to login")
    void unauthenticatedRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/dashboard"))
               .andExpect(status().is3xxRedirection());
    }

    @Test
    @DisplayName("Authenticated user can access dashboard")
    @WithMockUser(username = "oauth2user@gmail.com")
    void authenticatedUserCanAccessDashboard() throws Exception {
        mockMvc.perform(get("/dashboard"))
               .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Public home page accessible")
    void homePageAccessible() throws Exception {
        mockMvc.perform(get("/"))
               .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Login page shows OAuth2 options")
    void loginPageAccessible() throws Exception {
        mockMvc.perform(get("/login"))
               .andExpect(status().isOk());
    }
}
