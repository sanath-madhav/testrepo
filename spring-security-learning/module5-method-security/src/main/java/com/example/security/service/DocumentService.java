package com.example.security.service;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Demonstrates all method-level security annotations with real examples.
 */
@Service
public class DocumentService {

    // In-memory "database" of documents with owners
    private final Map<Long, Document> documents = new java.util.HashMap<>(Map.of(
        1L, new Document(1L, "Public Report", "user", false),
        2L, new Document(2L, "Admin Secret", "admin", true),
        3L, new Document(3L, "User Data", "user", false),
        4L, new Document(4L, "Manager Report", "manager", false)
    ));

    // ============================================================
    // @PreAuthorize - Check BEFORE method executes
    // Most flexible: full SpEL expression support
    // ============================================================

    @PreAuthorize("hasRole('ADMIN')")
    public List<Document> getAllDocuments() {
        return new ArrayList<>(documents.values());
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public Document getConfidentialDocument(Long id) {
        return documents.get(id);
    }

    // Access method parameter in SpEL with #paramName
    @PreAuthorize("hasRole('ADMIN') or #username == authentication.name")
    public List<Document> getDocumentsByOwner(String username) {
        return documents.values().stream()
            .filter(d -> d.owner().equals(username))
            .toList();
    }

    // ============================================================
    // @PostAuthorize - Check AFTER method executes, access returnObject
    // Use when you need to check properties of the return value
    // CAUTION: method executes even if check fails (potential side effects)
    // ============================================================

    @PostAuthorize("returnObject.owner == authentication.name or hasRole('ADMIN')")
    public Document getDocument(Long id) {
        return documents.get(id);
    }

    // ============================================================
    // @PreFilter - Filter INPUT collection before method executes
    // filterObject = each element in the collection
    // ============================================================

    @PreFilter("filterObject.owner == authentication.name or hasRole('ADMIN')")
    public List<Document> processDocuments(List<Document> docs) {
        // Only documents passing the filter are included
        return docs;
    }

    // ============================================================
    // @PostFilter - Filter OUTPUT collection after method executes
    // Only elements passing the filter are returned to caller
    // ============================================================

    @PostFilter("filterObject.owner == authentication.name or hasRole('ADMIN')")
    public List<Document> getUserDocuments() {
        return new ArrayList<>(documents.values());
    }

    // ============================================================
    // @Secured - Simpler, role-based (Spring-proprietary)
    // Only supports role names (no SpEL), less flexible
    // ============================================================

    @Secured({"ROLE_ADMIN", "ROLE_MANAGER"})
    public void archiveDocument(Long id) {
        // Only ADMIN or MANAGER can archive
        documents.remove(id);
    }

    // ============================================================
    // @RolesAllowed - JSR-250 standard annotation
    // Same as @Secured but uses standard Java EE annotation
    // ============================================================

    @RolesAllowed({"ADMIN", "MANAGER"}) // No "ROLE_" prefix needed
    public Document createDocument(Document doc) {
        documents.put(doc.id(), doc);
        return doc;
    }

    // ============================================================
    // Complex SpEL: Bean reference with @beanName
    // ============================================================

    @PreAuthorize("@documentPermissionEvaluator.canRead(authentication, #id)")
    public Document getDocumentWithCustomCheck(Long id) {
        return documents.get(id);
    }

    // ============================================================
    // hasPermission() - Custom permission evaluation
    // ============================================================

    @PreAuthorize("hasPermission(#id, 'Document', 'READ')")
    public Document getDocumentByPermission(Long id) {
        return documents.get(id);
    }

    public record Document(Long id, String title, String owner, boolean confidential) {}
}
