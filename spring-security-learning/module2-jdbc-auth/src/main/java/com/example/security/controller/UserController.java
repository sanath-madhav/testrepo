package com.example.security.controller;

import com.example.security.entity.AppUser;
import com.example.security.service.UserRegistrationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@Tag(name = "User Management", description = "User registration and profile APIs")
public class UserController {

    private final UserRegistrationService registrationService;

    public UserController(UserRegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegistrationRequest request) {
        AppUser user = registrationService.registerUser(request);
        return ResponseEntity.ok(Map.of(
            "message", "User registered successfully",
            "username", user.getUsername()
        ));
    }

    @GetMapping("/profile")
    @Operation(summary = "Get current user profile")
    public ResponseEntity<Map<String, Object>> getProfile(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
            "username", authentication.getName(),
            "authorities", authentication.getAuthorities().toString(),
            "authenticated", authentication.isAuthenticated()
        ));
    }

    @GetMapping("/admin/users")
    @Operation(summary = "Admin: list all users (requires ADMIN role)")
    public ResponseEntity<Map<String, String>> adminOnly(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
            "message", "Admin endpoint accessed",
            "by", authentication.getName()
        ));
    }
}
