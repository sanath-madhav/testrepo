package com.example.security.controller;

import com.example.security.entity.RefreshToken;
import com.example.security.service.RefreshTokenService;
import com.example.security.service.RefreshTokenService.RefreshTokenException;
import com.example.security.service.UserDetailsServiceImpl;
import com.example.security.util.AccessTokenUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Complete token lifecycle: login → refresh (with rotation) → logout
 */
@RestController
@RequestMapping("/auth")
@Tag(name = "Token Lifecycle", description = "Login, refresh with rotation, logout")
public class TokenController {

    private final AuthenticationManager authenticationManager;
    private final AccessTokenUtil accessTokenUtil;
    private final RefreshTokenService refreshTokenService;
    private final UserDetailsServiceImpl userDetailsService;

    public TokenController(AuthenticationManager authenticationManager,
                           AccessTokenUtil accessTokenUtil,
                           RefreshTokenService refreshTokenService,
                           UserDetailsServiceImpl userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.accessTokenUtil = accessTokenUtil;
        this.refreshTokenService = refreshTokenService;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    @Operation(summary = "Login — returns access token (15min) + refresh token (7days)")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
            );
            UserDetails userDetails = (UserDetails) auth.getPrincipal();

            String accessToken = accessTokenUtil.generateAccessToken(userDetails);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails);

            return ResponseEntity.ok(Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken.getToken(),
                "tokenType", "Bearer",
                "accessExpiresIn", "900 seconds",
                "refreshExpiresIn", "7 days",
                "note", "Store refreshToken securely (HttpOnly cookie preferred)"
            ));
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials"));
        }
    }

    @PostMapping("/refresh")
    @Operation(summary = "Rotate refresh token — old token invalidated, new pair issued")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {
        try {
            // Rotate: validate old token, issue new token, revoke old
            RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(
                request.refreshToken()
            );

            // Load user for new access token
            UserDetails userDetails = userDetailsService.loadUserByUsername(
                newRefreshToken.getUsername()
            );
            String newAccessToken = accessTokenUtil.generateAccessToken(userDetails);

            return ResponseEntity.ok(Map.of(
                "accessToken", newAccessToken,
                "refreshToken", newRefreshToken.getToken(),
                "tokenType", "Bearer",
                "note", "Previous refresh token is now invalid (rotation)"
            ));
        } catch (RefreshTokenException ex) {
            // Token stolen or expired — force re-login
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", ex.getMessage(), "action", "Please log in again"));
        }
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout — revokes entire token family (all devices)")
    public ResponseEntity<?> logout(@RequestBody RefreshRequest request) {
        refreshTokenService.revokeFamily(request.refreshToken());
        return ResponseEntity.ok(Map.of(
            "message", "Logged out. All sessions for this login revoked.",
            "note", "Access token will still work until it expires (15 min). " +
                    "Use a token blacklist to revoke access tokens immediately."
        ));
    }

    @PostMapping("/logout-all")
    @Operation(summary = "Logout from ALL devices — revokes all user's refresh tokens")
    public ResponseEntity<?> logoutAll(@RequestBody LogoutAllRequest request) {
        refreshTokenService.revokeAllForUser(request.username());
        return ResponseEntity.ok(Map.of("message", "All sessions for user revoked"));
    }

    public record LoginRequest(String username, String password) {}
    public record RefreshRequest(String refreshToken) {}
    public record LogoutAllRequest(String username) {}
}
