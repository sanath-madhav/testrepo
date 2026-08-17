package com.example.security.service;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;

/**
 * CONCEPT: Custom PermissionEvaluator for hasPermission() SpEL
 *
 * Enables fine-grained, domain object-level security:
 * @PreAuthorize("hasPermission(#document, 'WRITE')")
 * @PreAuthorize("hasPermission(#id, 'Document', 'DELETE')")
 *
 * hasPermission(targetObject, permission) -> evaluate(auth, targetObject, permission)
 * hasPermission(id, type, permission) -> evaluate(auth, id, type, permission)
 *
 * Also referenced directly in SpEL:
 * @PreAuthorize("@documentPermissionEvaluator.canRead(authentication, #id)")
 */
@Component("documentPermissionEvaluator")
public class DocumentPermissionEvaluator implements PermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication authentication,
                                  Object targetDomainObject,
                                  Object permission) {
        if (targetDomainObject instanceof DocumentService.Document doc) {
            return switch (permission.toString()) {
                case "READ" -> !doc.confidential() || authentication.getAuthorities()
                    .stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
                case "WRITE" -> authentication.getAuthorities()
                    .stream().anyMatch(a ->
                        a.getAuthority().equals("ROLE_ADMIN") ||
                        a.getAuthority().equals("ROLE_MANAGER"));
                case "DELETE" -> authentication.getAuthorities()
                    .stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
                default -> false;
            };
        }
        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication,
                                  Serializable targetId,
                                  String targetType,
                                  Object permission) {
        // Look up domain object by ID, then delegate to the above method
        // In real app: load from DB, check ownership, etc.
        return authentication.isAuthenticated();
    }

    public boolean canRead(Authentication authentication, Long id) {
        // Custom business logic: admins can read all, others only their own
        return authentication.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))
            || id <= 2; // example: public documents have ID <= 2
    }
}
