package com.example.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class JdbcAuthTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("DB user can authenticate via HTTP Basic")
    void dbUserAuthenticates() throws Exception {
        mockMvc.perform(get("/api/profile")
               .with(httpBasic("dbuser", "password")))
               .andExpect(status().isOk())
               .andExpect(jsonPath("$.username").value("dbuser"));
    }

    @Test
    @DisplayName("DB admin can access admin endpoint")
    void dbAdminAccessesAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/admin/users")
               .with(httpBasic("dbadmin", "admin123")))
               .andExpect(status().isOk());
    }

    @Test
    @DisplayName("DB user cannot access admin endpoint")
    void dbUserCannotAccessAdmin() throws Exception {
        mockMvc.perform(get("/api/admin/users")
               .with(httpBasic("dbuser", "password")))
               .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Registration creates a new user")
    void registrationCreatesUser() throws Exception {
        String body = """
                {"username": "newuser", "password": "newpass123"}
                """;
        mockMvc.perform(post("/api/register")
               .contentType(MediaType.APPLICATION_JSON)
               .content(body))
               .andExpect(status().isOk())
               .andExpect(jsonPath("$.username").value("newuser"));
    }

    @Test
    @DisplayName("Wrong password returns 401")
    void wrongPasswordReturns401() throws Exception {
        mockMvc.perform(get("/api/profile")
               .with(httpBasic("dbuser", "wrongpass")))
               .andExpect(status().isUnauthorized());
    }
}
