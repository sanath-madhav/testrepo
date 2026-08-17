package com.example.security.controller;

import com.example.security.service.AuditService;
import com.example.security.util.JwtUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "Login endpoint with brute force protection")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final AuditService auditService;

    public AuthController(AuthenticationManager authenticationManager,
                          JwtUtil jwtUtil,
                          AuditService auditService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.auditService = auditService;
    }

    @PostMapping("/login")
    @Operation(summary = "Login — with brute force protection and audit logging")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
            );
            UserDetails userDetails = (UserDetails) auth.getPrincipal();
            String token = jwtUtil.generateToken(userDetails);

            return ResponseEntity.ok(Map.of(
                "token", token,
                "tokenType", "Bearer",
                "username", userDetails.getUsername(),
                "roles", userDetails.getAuthorities().stream()
                    .map(a -> a.getAuthority()).toList()
            ));
        } catch (LockedException ex) {
            auditService.log("LOGIN_FAILURE_LOCKED", request.username(),
                "Login attempted on locked account");
            return ResponseEntity.status(HttpStatus.LOCKED)
                .body(Map.of("error", "Account is temporarily locked", "retry", "15 minutes"));
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials",
                             "hint", ex.getMessage()));
        }
    }

    public record LoginRequest(String username, String password) {}
}
