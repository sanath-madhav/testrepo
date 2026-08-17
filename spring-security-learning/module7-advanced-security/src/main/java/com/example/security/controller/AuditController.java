package com.example.security.controller;

import com.example.security.entity.AuditEvent;
import com.example.security.service.AuditService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/audit")
@Tag(name = "Audit Log", description = "Security event audit trail — ADMIN only")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/recent")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get 50 most recent security events")
    public ResponseEntity<List<AuditEvent>> recentEvents() {
        return ResponseEntity.ok(auditService.getRecentEvents());
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasRole('ADMIN') or #username == authentication.name")
    @Operation(summary = "Get security events for a specific user (ADMIN or self)")
    public ResponseEntity<?> eventsForUser(@PathVariable String username,
                                           @AuthenticationPrincipal UserDetails currentUser) {
        List<AuditEvent> events = auditService.getEventsForUser(username);
        return ResponseEntity.ok(Map.of(
            "username", username,
            "eventCount", events.size(),
            "events", events
        ));
    }
}
