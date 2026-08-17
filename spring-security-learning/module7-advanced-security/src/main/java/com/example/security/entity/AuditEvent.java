package com.example.security.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Persisted security audit log entry.
 * Records authentication events for compliance and forensic analysis.
 */
@Entity
@Table(name = "audit_events",
    indexes = @Index(name = "idx_audit_username", columnList = "username"))
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String eventType;   // LOGIN_SUCCESS, LOGIN_FAILURE, ACCOUNT_LOCKED, LOGOUT, etc.

    private String username;
    private String ipAddress;
    private String userAgent;
    private String details;

    @Column(nullable = false)
    private Instant timestamp = Instant.now();

    protected AuditEvent() {}

    public AuditEvent(String eventType, String username, String ipAddress, String details) {
        this.eventType = eventType;
        this.username = username;
        this.ipAddress = ipAddress;
        this.details = details;
    }

    public Long getId() { return id; }
    public String getEventType() { return eventType; }
    public String getUsername() { return username; }
    public String getIpAddress() { return ipAddress; }
    public String getUserAgent() { return userAgent; }
    public String getDetails() { return details; }
    public Instant getTimestamp() { return timestamp; }

    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
}
