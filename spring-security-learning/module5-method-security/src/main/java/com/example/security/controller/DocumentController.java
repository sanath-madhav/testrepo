package com.example.security.controller;

import com.example.security.service.DocumentService;
import com.example.security.service.DocumentService.Document;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/documents")
@Tag(name = "Document API", description = "Demonstrates method-level security annotations")
public class DocumentController {

    private final DocumentService documentService;

    public DocumentController(DocumentService documentService) {
        this.documentService = documentService;
    }

    @GetMapping
    @Operation(summary = "Get all documents (ADMIN only - @PreAuthorize)")
    public ResponseEntity<List<Document>> getAllDocuments() {
        return ResponseEntity.ok(documentService.getAllDocuments());
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get document by ID (@PostAuthorize - owner or ADMIN)")
    public ResponseEntity<Document> getDocument(@PathVariable Long id) {
        Document doc = documentService.getDocument(id);
        if (doc == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(doc);
    }

    @GetMapping("/owner/{username}")
    @Operation(summary = "Get documents by owner (@PreAuthorize with param)")
    public ResponseEntity<List<Document>> getByOwner(@PathVariable String username) {
        return ResponseEntity.ok(documentService.getDocumentsByOwner(username));
    }

    @GetMapping("/my")
    @Operation(summary = "Get my documents (@PostFilter)")
    public ResponseEntity<List<Document>> getMyDocuments() {
        return ResponseEntity.ok(documentService.getUserDocuments());
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Archive document (@Secured)")
    public ResponseEntity<Void> archiveDocument(@PathVariable Long id) {
        documentService.archiveDocument(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping
    @Operation(summary = "Create document (@RolesAllowed)")
    public ResponseEntity<Document> createDocument(@RequestBody Document doc) {
        return ResponseEntity.ok(documentService.createDocument(doc));
    }
}
