package com.example.security.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@Tag(name = "Protected Resources", description = "JWT-protected endpoints")
@SecurityRequirement(name = "bearerAuth")
public class ProtectedController {

    @GetMapping("/profile")
    @Operation(summary = "Get authenticated user's profile")
    public Map<String, Object> getProfile(Authentication authentication) {
        return Map.of(
            "username", authentication.getName(),
            "authorities", authentication.getAuthorities().toString(),
            "authenticated", true
        );
    }

    @GetMapping("/resource")
    @Operation(summary = "Access a protected resource")
    public Map<String, String> getResource() {
        return Map.of("data", "This is protected data, only accessible with valid JWT");
    }

    @GetMapping("/admin/secret")
    @Operation(summary = "Admin-only endpoint")
    public Map<String, String> adminSecret(Authentication authentication) {
        return Map.of(
            "secret", "TOP SECRET ADMIN DATA",
            "accessedBy", authentication.getName()
        );
    }
}
