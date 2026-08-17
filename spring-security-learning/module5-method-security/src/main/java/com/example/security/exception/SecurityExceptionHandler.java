package com.example.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Map;

/**
 * CONCEPT: Security Exception Handling
 *
 * Spring Security exceptions flow:
 *
 * AuthenticationException (401 Unauthorized):
 * - UsernameNotFoundException: user not found
 * - BadCredentialsException: wrong password
 * - AccountExpiredException, LockedException, etc.
 * - Handled by: AuthenticationEntryPoint
 *   Default: redirect to /login (web) or 401 (REST)
 *
 * AccessDeniedException (403 Forbidden):
 * - User is authenticated but lacks required role/permission
 * - Thrown by: @PreAuthorize, hasRole() in SecurityFilterChain
 * - Handled by: AccessDeniedHandler
 *   Default: redirect to /access-denied or 403 response
 *
 * Both exceptions are caught by ExceptionTranslationFilter in the
 * Spring Security filter chain, which delegates to the configured handlers.
 *
 * For REST APIs: configure custom handlers to return JSON error responses.
 */
@RestControllerAdvice
public class SecurityExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(
            AccessDeniedException ex, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(Map.of(
                "timestamp", Instant.now(),
                "status", 403,
                "error", "Forbidden",
                "message", "Access denied: insufficient privileges",
                "path", request.getRequestURI()
            ));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleAuthenticationException(
            AuthenticationException ex, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of(
                "timestamp", Instant.now(),
                "status", 401,
                "error", "Unauthorized",
                "message", "Authentication required",
                "path", request.getRequestURI()
            ));
    }
}
