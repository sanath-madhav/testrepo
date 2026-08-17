package com.example.security.controller;

import com.example.security.util.JwtUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * CONCEPT: JWT Login Endpoint
 *
 * Unlike form login (handled by Spring Security filters automatically),
 * JWT login requires a manual AuthController:
 *
 * 1. Client POST /auth/login with {username, password}
 * 2. Controller calls AuthenticationManager.authenticate()
 * 3. AuthenticationManager verifies credentials via UserDetailsService
 * 4. On success: JwtUtil generates a signed JWT
 * 5. JWT is returned to client in response body
 * 6. Client stores JWT (localStorage / memory) and sends it in every request
 *    Authorization: Bearer <jwt_token>
 */
@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "JWT login and token refresh")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    @Operation(summary = "Login and receive JWT tokens")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest request) {
        try {
            // Attempt authentication — throws AuthenticationException if invalid
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.username(),
                    request.password()
                )
            );

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            String accessToken = jwtUtil.generateToken(userDetails);
            String refreshToken = jwtUtil.generateRefreshToken(userDetails);

            return ResponseEntity.ok(Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken,
                "tokenType", "Bearer",
                "username", userDetails.getUsername()
            ));
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials"));
        }
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token using refresh token")
    public ResponseEntity<Map<String, String>> refresh(@RequestBody RefreshRequest request) {
        String username = jwtUtil.extractUsername(request.refreshToken());

        if (username != null && !jwtUtil.isTokenExpired(request.refreshToken())) {
            // In a real app, validate refresh token against a DB whitelist
            return ResponseEntity.ok(Map.of(
                "accessToken", "new_access_token_here",
                "tokenType", "Bearer"
            ));
        }

        return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired refresh token"));
    }

    public record LoginRequest(String username, String password) {}
    public record RefreshRequest(String refreshToken) {}
}
