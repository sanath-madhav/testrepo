package com.example.security.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * REST API controller demonstrating HTTP Basic Authentication.
 * Returns JSON responses instead of HTML views.
 */
@RestController
@RequestMapping("/api")
@Tag(name = "Basic Security API", description = "Endpoints demonstrating basic Spring Security")
@SecurityRequirement(name = "basicAuth")
public class ApiController {

    @GetMapping("/public")
    @Operation(summary = "Public endpoint - no authentication required")
    public Map<String, String> publicEndpoint() {
        return Map.of(
            "message", "This is a public endpoint",
            "access", "anyone"
        );
    }

    @GetMapping("/user")
    @Operation(summary = "User endpoint - requires authentication")
    public Map<String, Object> userEndpoint(Authentication authentication) {
        return Map.of(
            "message", "Hello, authenticated user!",
            "username", authentication.getName(),
            "authorities", authentication.getAuthorities().toString()
        );
    }

    @GetMapping("/admin")
    @Operation(summary = "Admin endpoint - requires ADMIN role")
    public Map<String, String> adminEndpoint(Authentication authentication) {
        return Map.of(
            "message", "Admin area - sensitive data",
            "username", authentication.getName()
        );
    }

    @GetMapping("/whoami")
    @Operation(summary = "Returns current user info")
    public Map<String, Object> whoAmI(Authentication authentication) {
        return Map.of(
            "principal", authentication.getName(),
            "credentials", "[PROTECTED]",
            "authorities", authentication.getAuthorities(),
            "authenticated", authentication.isAuthenticated(),
            "class", authentication.getClass().getSimpleName()
        );
    }
}
