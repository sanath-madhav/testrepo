package com.example.security;

import com.example.security.service.DocumentService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.test.context.support.WithMockUser;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testing method security directly on the service layer.
 */
@SpringBootTest
class MethodSecurityTest {

    @Autowired
    private DocumentService documentService;

    @Test
    @DisplayName("Admin can get all documents")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void adminGetsAllDocuments() {
        var docs = documentService.getAllDocuments();
        assertFalse(docs.isEmpty(), "Admin should see all documents");
    }

    @Test
    @DisplayName("User without ADMIN role cannot get all documents")
    @WithMockUser(username = "user", roles = {"USER"})
    void userCannotGetAllDocuments() {
        assertThrows(AccessDeniedException.class, () ->
            documentService.getAllDocuments(),
            "Regular user should not access all documents"
        );
    }

    @Test
    @DisplayName("User can get their own documents")
    @WithMockUser(username = "user", roles = {"USER"})
    void userGetsOwnDocuments() {
        var docs = documentService.getDocumentsByOwner("user");
        assertTrue(docs.stream().allMatch(d -> d.owner().equals("user")));
    }

    @Test
    @DisplayName("User cannot get another user's documents")
    @WithMockUser(username = "user", roles = {"USER"})
    void userCannotGetOtherDocuments() {
        assertThrows(AccessDeniedException.class, () ->
            documentService.getDocumentsByOwner("admin")
        );
    }

    @Test
    @DisplayName("Admin can get any user's documents")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void adminGetsAnyUserDocuments() {
        var docs = documentService.getDocumentsByOwner("user");
        assertNotNull(docs);
    }

    @Test
    @DisplayName("PostFilter: user only sees their own documents")
    @WithMockUser(username = "user", roles = {"USER"})
    void postFilterReturnsOnlyOwnDocuments() {
        var docs = documentService.getUserDocuments();
        assertTrue(docs.stream().allMatch(d -> d.owner().equals("user")),
            "PostFilter should only return user's own documents");
    }

    @Test
    @DisplayName("Admin cannot archive (only MANAGER or ADMIN)")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void adminCanArchive() {
        assertDoesNotThrow(() -> documentService.archiveDocument(1L));
    }

    @Test
    @DisplayName("USER role cannot archive documents")
    @WithMockUser(username = "user", roles = {"USER"})
    void userCannotArchive() {
        assertThrows(AccessDeniedException.class, () ->
            documentService.archiveDocument(1L)
        );
    }
}
