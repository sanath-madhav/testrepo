package com.example.security.repository;

import com.example.security.entity.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {
    List<AuditEvent> findByUsernameOrderByTimestampDesc(String username);
    List<AuditEvent> findByEventTypeAndTimestampAfterOrderByTimestampDesc(String eventType, Instant after);
    List<AuditEvent> findTop50ByOrderByTimestampDesc();
}
