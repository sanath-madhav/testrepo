package com.example.security.service;

import com.example.security.entity.AuditEvent;
import com.example.security.repository.AuditEventRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;

/**
 * Central audit logging service for security events.
 *
 * Event types:
 * - LOGIN_SUCCESS / LOGIN_FAILURE
 * - ACCOUNT_LOCKED / ACCOUNT_UNLOCKED
 * - ACCESS_DENIED / UNAUTHORIZED_ACCESS
 * - PASSWORD_CHANGED / PASSWORD_POLICY_VIOLATION
 * - SESSION_CREATED / SESSION_EXPIRED / SESSION_CONCURRENT_LIMIT
 * - TOKEN_REFRESH / TOKEN_REVOKED
 * - ROLE_ESCALATION_ATTEMPT
 *
 * Compliance use cases: PCI-DSS (10.2), HIPAA, SOC2, ISO 27001.
 * Audit records should be immutable and stored separately from the main DB.
 *
 * Uses REQUIRES_NEW propagation so audit records are committed even if the
 * calling transaction rolls back.
 */
@Service
public class AuditService {

    private final AuditEventRepository auditEventRepository;

    public AuditService(AuditEventRepository auditEventRepository) {
        this.auditEventRepository = auditEventRepository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(String eventType, String username, String details) {
        String ipAddress = extractIpAddress();
        AuditEvent event = new AuditEvent(eventType, username, ipAddress, details);

        String userAgent = extractUserAgent();
        if (userAgent != null) event.setUserAgent(userAgent);

        auditEventRepository.save(event);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> getEventsForUser(String username) {
        return auditEventRepository.findByUsernameOrderByTimestampDesc(username);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> getRecentEvents() {
        return auditEventRepository.findTop50ByOrderByTimestampDesc();
    }

    private String extractIpAddress() {
        try {
            ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) return "unknown";
            HttpServletRequest request = attrs.getRequest();
            // Check for proxy-forwarded IP
            String xff = request.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isEmpty()) {
                return xff.split(",")[0].trim();
            }
            return request.getRemoteAddr();
        } catch (Exception e) {
            return "unknown";
        }
    }

    private String extractUserAgent() {
        try {
            ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) return null;
            return attrs.getRequest().getHeader("User-Agent");
        } catch (Exception e) {
            return null;
        }
    }
}
