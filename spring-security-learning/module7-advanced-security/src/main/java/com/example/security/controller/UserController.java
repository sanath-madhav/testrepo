package com.example.security.controller;

import com.example.security.service.PasswordPolicyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Demonstrates:
 * 1. @AuthenticationPrincipal — injects the current UserDetails without SecurityContextHolder
 * 2. Role hierarchy effects (MANAGER endpoint accessible to ADMIN)
 * 3. Method-level security annotations
 * 4. Password policy enforcement via service
 *
 * @AuthenticationPrincipal deep-dive:
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * Old way (verbose, couples to security infrastructure):
 *   Authentication auth = SecurityContextHolder.getContext().getAuthentication();
 *   UserDetails user = (UserDetails) auth.getPrincipal();
 *
 * New way (clean, testable with @WithMockUser):
 *   public ResponseEntity<?> profile(@AuthenticationPrincipal UserDetails userDetails)
 *
 * Works for custom UserDetails implementations too:
 *   public ResponseEntity<?> profile(@AuthenticationPrincipal CustomUserDetails user)
 *   → Spring injects the actual principal object, cast to your type
 *
 * Spring SpEL in @AuthenticationPrincipal:
 *   @AuthenticationPrincipal(expression = "#this == 'anonymousUser' ? null : principal")
 *   → handles anonymous access gracefully
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 */
@RestController
@Tag(name = "User Endpoints", description = "Demonstrates role hierarchy and @AuthenticationPrincipal")
public class UserController {

    private final PasswordPolicyService passwordPolicyService;

    public UserController(PasswordPolicyService passwordPolicyService) {
        this.passwordPolicyService = passwordPolicyService;
    }

    @GetMapping("/api/me")
    @Operation(summary = "Get current user profile using @AuthenticationPrincipal")
    public ResponseEntity<?> profile(@AuthenticationPrincipal UserDetails currentUser) {
        return ResponseEntity.ok(Map.of(
            "username", currentUser.getUsername(),
            "roles", currentUser.getAuthorities().stream()
                .map(a -> a.getAuthority()).toList(),
            "accountNonLocked", currentUser.isAccountNonLocked(),
            "note", "Injected via @AuthenticationPrincipal — no SecurityContextHolder needed"
        ));
    }

    @GetMapping("/api/manager/dashboard")
    @PreAuthorize("hasRole('MANAGER')") // ADMIN also passes due to role hierarchy
    @Operation(summary = "Manager dashboard — accessible by MANAGER and ADMIN (role hierarchy)")
    public ResponseEntity<?> managerDashboard(@AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(Map.of(
            "dashboard", "Manager Dashboard",
            "accessedBy", user.getUsername(),
            "effectiveRoles", user.getAuthorities().stream().map(a -> a.getAuthority()).toList(),
            "roleHierarchyNote", "ROLE_ADMIN > ROLE_MANAGER > ROLE_USER. " +
                "ADMIN can access this endpoint without explicitly having ROLE_MANAGER."
        ));
    }

    @GetMapping("/api/admin/dashboard")
    @Secured("ROLE_ADMIN")
    @Operation(summary = "Admin dashboard — ADMIN only")
    public ResponseEntity<?> adminDashboard(@AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(Map.of(
            "dashboard", "Admin Dashboard",
            "accessedBy", user.getUsername()
        ));
    }

    @GetMapping("/api/user/data")
    @PreAuthorize("hasRole('USER')") // accessible by USER, MANAGER, ADMIN
    @Operation(summary = "User data — accessible by all authenticated roles (hierarchy)")
    public ResponseEntity<?> userData(@AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(Map.of(
            "data", "User-level data",
            "accessedBy", user.getUsername()
        ));
    }

    @PostMapping("/api/public/password-check")
    @Operation(summary = "Check password strength and policy compliance")
    public ResponseEntity<?> checkPassword(@RequestBody PasswordCheckRequest request) {
        var result = passwordPolicyService.validate(request.password(), request.username());
        int strength = passwordPolicyService.calculateStrength(request.password());
        return ResponseEntity.ok(Map.of(
            "valid", result.valid(),
            "violations", result.violations(),
            "strength", strength,
            "strengthLabel", strengthLabel(strength)
        ));
    }

    private String strengthLabel(int score) {
        return switch (score) {
            case 0, 1 -> "Very Weak";
            case 2 -> "Weak";
            case 3 -> "Fair";
            case 4 -> "Strong";
            default -> "Very Strong";
        };
    }

    public record PasswordCheckRequest(String password, String username) {}
}
