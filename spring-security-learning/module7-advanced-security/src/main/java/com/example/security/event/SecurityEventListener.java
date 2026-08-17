package com.example.security.event;

import com.example.security.service.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

/**
 * Listens to Spring Security authentication events and delegates to AuditService.
 *
 * Spring Security publishes events via ApplicationEventPublisher whenever
 * authentication succeeds or fails. These events are part of the
 * org.springframework.security.authentication.event package.
 *
 * Key events:
 * ┌─────────────────────────────────────────┬──────────────────────────────────────────────────┐
 * │ Event                                   │ When fired                                       │
 * ├─────────────────────────────────────────┼──────────────────────────────────────────────────┤
 * │ AuthenticationSuccessEvent              │ Login succeeded                                  │
 * │ AuthenticationFailureBadCredentialsEvent│ Wrong password or unknown user                   │
 * │ AuthenticationFailureLockedEvent        │ Account is locked                                │
 * │ AuthenticationFailureDisabledEvent      │ Account is disabled                              │
 * │ AuthenticationFailureExpiredEvent       │ Credentials or account expired                   │
 * │ InteractiveAuthenticationSuccessEvent   │ Login via form/HTTP Basic (not remember-me)      │
 * └─────────────────────────────────────────┴──────────────────────────────────────────────────┘
 *
 * Why use events instead of checking in the controller?
 * - Decouples audit logic from business logic
 * - Catches ALL authentication paths (form login, HTTP Basic, JWT filter, remember-me)
 * - Spring's event system is synchronous by default — events fire in the same thread
 *   (use @Async + @EnableAsync if you need non-blocking audit writes)
 *
 * Note: For JWT-based auth (stateless), these events only fire when
 * AuthenticationManager.authenticate() is called (e.g., during /auth/login).
 * They do NOT fire on every JWT-validated request. For per-request auditing,
 * use a filter or AOP interceptor.
 */
@Component
public class SecurityEventListener {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventListener.class);

    private final AuditService auditService;

    public SecurityEventListener(AuditService auditService) {
        this.auditService = auditService;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        log.info("AUTH_SUCCESS: user={}", username);
        auditService.log("LOGIN_SUCCESS", username,
            "Roles: " + event.getAuthentication().getAuthorities());
    }

    @EventListener
    public void onBadCredentials(AuthenticationFailureBadCredentialsEvent event) {
        String username = event.getAuthentication().getName();
        log.warn("AUTH_FAILURE_BAD_CREDENTIALS: user={}", username);
        auditService.log("LOGIN_FAILURE", username, "Bad credentials");
    }

    @EventListener
    public void onLocked(AuthenticationFailureLockedEvent event) {
        String username = event.getAuthentication().getName();
        log.warn("AUTH_FAILURE_LOCKED: user={}", username);
        auditService.log("ACCOUNT_LOCKED_LOGIN_ATTEMPT", username,
            "Login attempted on locked account");
    }

    @EventListener
    public void onDisabled(AuthenticationFailureDisabledEvent event) {
        String username = event.getAuthentication().getName();
        log.warn("AUTH_FAILURE_DISABLED: user={}", username);
        auditService.log("LOGIN_FAILURE_DISABLED", username, "Account is disabled");
    }

    @EventListener
    public void onExpired(AuthenticationFailureExpiredEvent event) {
        String username = event.getAuthentication().getName();
        log.warn("AUTH_FAILURE_EXPIRED: user={}", username);
        auditService.log("LOGIN_FAILURE_CREDENTIALS_EXPIRED", username, "Credentials expired");
    }
}
