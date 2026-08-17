package com.example.security;

import com.example.security.util.JwtUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class JwtAuthTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Login with valid credentials returns JWT")
    void loginReturnsJwt() throws Exception {
        mockMvc.perform(post("/auth/login")
               .contentType(MediaType.APPLICATION_JSON)
               .content("""
                   {"username": "jwtuser", "password": "password"}
                   """))
               .andExpect(status().isOk())
               .andExpect(jsonPath("$.accessToken").isNotEmpty())
               .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    @DisplayName("Access protected resource without JWT returns 401")
    void noJwtReturns401() throws Exception {
        mockMvc.perform(get("/api/profile"))
               .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Access protected resource with valid JWT succeeds")
    void validJwtAllowsAccess() throws Exception {
        // Step 1: Login to get token
        MvcResult loginResult = mockMvc.perform(post("/auth/login")
               .contentType(MediaType.APPLICATION_JSON)
               .content("""
                   {"username": "jwtuser", "password": "password"}
                   """))
               .andReturn();

        String responseBody = loginResult.getResponse().getContentAsString();
        // Extract token from JSON response
        String token = responseBody.split("\"accessToken\":\"")[1].split("\"")[0];

        // Step 2: Use token to access protected resource
        mockMvc.perform(get("/api/profile")
               .header("Authorization", "Bearer " + token))
               .andExpect(status().isOk())
               .andExpect(jsonPath("$.username").value("jwtuser"));
    }

    @Test
    @DisplayName("Mock user can access protected endpoint")
    @WithMockUser(username = "testuser", roles = {"USER"})
    void mockUserAccessesProtectedEndpoint() throws Exception {
        mockMvc.perform(get("/api/resource"))
               .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Invalid credentials returns 401")
    void invalidCredentialsReturn401() throws Exception {
        mockMvc.perform(post("/auth/login")
               .contentType(MediaType.APPLICATION_JSON)
               .content("""
                   {"username": "jwtuser", "password": "wrongpassword"}
                   """))
               .andExpect(status().isUnauthorized());
    }
}
