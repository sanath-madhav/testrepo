package com.example.security.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Educational guide to advanced Spring Security concepts.
 * All endpoints are public — for learning purposes.
 */
@RestController
@RequestMapping("/api/public/concepts")
@Tag(name = "Security Concepts Guide",
     description = "Educational guide covering advanced Spring Security patterns")
public class SecurityConceptsController {

    @GetMapping("/role-hierarchy")
    @Operation(summary = "Role hierarchy — how ADMIN inherits MANAGER and USER permissions")
    public ResponseEntity<?> roleHierarchyGuide() {
        return ResponseEntity.ok(Map.of(
            "concept", "Role Hierarchy",
            "definition", "Role hierarchy lets you define inheritance between roles. " +
                "A higher role automatically inherits all permissions of lower roles.",
            "configuration", Map.of(
                "hierarchy", "ROLE_ADMIN > ROLE_MANAGER > ROLE_MANAGER > ROLE_USER",
                "bean", "RoleHierarchyImpl.fromHierarchy(...)",
                "springBootAutoWiring", "Declared as @Bean named 'roleHierarchy' — " +
                    "Spring Security's expression evaluator picks it up automatically"
            ),
            "effect", List.of(
                "hasRole('USER') passes for USER, MANAGER, and ADMIN",
                "hasRole('MANAGER') passes for MANAGER and ADMIN",
                "hasRole('ADMIN') passes only for ADMIN",
                "No code changes needed in controllers — hierarchy is applied transparently"
            ),
            "withoutHierarchy", "You'd need: hasAnyRole('USER','MANAGER','ADMIN') for every USER check",
            "bestPractice", "Define hierarchy in SecurityConfig, not in @PreAuthorize expressions"
        ));
    }

    @GetMapping("/security-headers")
    @Operation(summary = "Security headers — CSP, HSTS, X-Frame-Options, etc.")
    public ResponseEntity<?> securityHeadersGuide() {
        return ResponseEntity.ok(Map.of(
            "concept", "HTTP Security Headers",
            "headers", List.of(
                Map.of(
                    "header", "Strict-Transport-Security (HSTS)",
                    "value", "max-age=31536000; includeSubDomains; preload",
                    "purpose", "Forces HTTPS. Browser never sends HTTP requests for 1 year.",
                    "attack_prevented", "SSL stripping, downgrade attacks",
                    "spring", ".httpStrictTransportSecurity(h -> h.maxAgeInSeconds(31536000))"
                ),
                Map.of(
                    "header", "Content-Security-Policy (CSP)",
                    "value", "default-src 'self'; script-src 'self'; object-src 'none'",
                    "purpose", "Controls allowed resource origins. Prevents XSS.",
                    "attack_prevented", "Cross-Site Scripting (XSS), data injection",
                    "spring", ".contentSecurityPolicy(csp -> csp.policyDirectives(\"...\"))"
                ),
                Map.of(
                    "header", "X-Frame-Options",
                    "value", "DENY",
                    "purpose", "Prevents page from being embedded in iframes.",
                    "attack_prevented", "Clickjacking",
                    "spring", ".frameOptions(f -> f.deny())"
                ),
                Map.of(
                    "header", "X-Content-Type-Options",
                    "value", "nosniff",
                    "purpose", "Browsers must use declared MIME type, no guessing.",
                    "attack_prevented", "MIME type confusion attacks",
                    "spring", ".contentTypeOptions(c -> {})"
                ),
                Map.of(
                    "header", "Referrer-Policy",
                    "value", "strict-origin-when-cross-origin",
                    "purpose", "Limits referrer information sent in cross-origin requests.",
                    "attack_prevented", "Referrer leakage, URL enumeration",
                    "spring", ".referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))"
                ),
                Map.of(
                    "header", "Permissions-Policy",
                    "value", "camera=(), microphone=(), geolocation=()",
                    "purpose", "Disables browser APIs the page doesn't use.",
                    "attack_prevented", "Browser feature abuse by malicious injected content",
                    "spring", ".permissionsPolicy(p -> p.policy(\"camera=(), microphone=()\"))"
                )
            ),
            "toolToTest", "curl -I https://yourhost/api/me | grep -i -E 'strict|content-security|x-frame|x-content|referrer|permissions'",
            "scoringTool", "https://securityheaders.com"
        ));
    }

    @GetMapping("/brute-force-protection")
    @Operation(summary = "Brute force protection strategies")
    public ResponseEntity<?> bruteForceGuide() {
        return ResponseEntity.ok(Map.of(
            "concept", "Brute Force Protection",
            "strategies", List.of(
                Map.of(
                    "approach", "Account Lockout (implemented here)",
                    "howItWorks", "Track failed attempts per user in DB. Lock after N failures.",
                    "pros", List.of("Simple", "Works across server restarts", "Provides audit trail"),
                    "cons", List.of("Can be used to DoS specific accounts", "Doesn't protect unknown usernames")
                ),
                Map.of(
                    "approach", "IP-Based Rate Limiting",
                    "howItWorks", "Limit requests per IP per time window.",
                    "implementation", "Spring Cloud Gateway, Bucket4j, Resilience4j",
                    "pros", List.of("Covers unknown usernames", "Prevents enumeration"),
                    "cons", List.of("Shared IPs (NAT, VPN) block legitimate users", "Bypassed with IP rotation")
                ),
                Map.of(
                    "approach", "Progressive Delay (Exponential Backoff)",
                    "howItWorks", "Increase delay between responses after each failure.",
                    "pros", List.of("User still can retry", "Non-disruptive"),
                    "cons", List.of("Complex to implement correctly at scale")
                ),
                Map.of(
                    "approach", "CAPTCHA after N failures",
                    "howItWorks", "Require CAPTCHA solving after 3-5 failures.",
                    "pros", List.of("Stops automated attacks while allowing human retry"),
                    "cons", List.of("Poor UX", "CAPTCHA solving services exist"))
            ),
            "implementation", Map.of(
                "provider", "CustomAuthenticationProvider",
                "service", "BruteForceProtectionService",
                "storage", "User.failedLoginAttempts + User.lockoutTime in DB",
                "autoUnlock", "Lockout expires after configurable duration (default: 15 min)",
                "config", "security.max-login-attempts=5, security.lockout-duration-minutes=15"
            )
        ));
    }

    @GetMapping("/authentication-principal")
    @Operation(summary = "@AuthenticationPrincipal — clean principal injection")
    public ResponseEntity<?> authPrincipalGuide() {
        return ResponseEntity.ok(Map.of(
            "concept", "@AuthenticationPrincipal",
            "purpose", "Injects the currently authenticated principal directly into controller methods",
            "oldWay", Map.of(
                "code", "Authentication auth = SecurityContextHolder.getContext().getAuthentication(); UserDetails user = (UserDetails) auth.getPrincipal();",
                "problems", List.of("Verbose", "Tightly coupled to SecurityContextHolder", "Harder to test")
            ),
            "newWay", Map.of(
                "code", "public ResponseEntity<?> method(@AuthenticationPrincipal UserDetails user)",
                "benefits", List.of(
                    "Clean, declarative",
                    "Works with @WithMockUser in tests",
                    "Works with custom UserDetails implementations",
                    "No security infrastructure imports in business logic"
                )
            ),
            "customUserDetails", Map.of(
                "code", "public ResponseEntity<?> method(@AuthenticationPrincipal CustomUser user)",
                "note", "Spring auto-casts to your custom type if that's what loadUserByUsername returns"
            ),
            "spelVariant", Map.of(
                "code", "@AuthenticationPrincipal(expression = \"#this == 'anonymousUser' ? null : principal\")",
                "use", "Handle anonymous access gracefully without null principal"
            )
        ));
    }

    @GetMapping("/session-management")
    @Operation(summary = "Session management — concurrent session control, fixation protection")
    public ResponseEntity<?> sessionManagementGuide() {
        return ResponseEntity.ok(Map.of(
            "concept", "Session Management",
            "sessionFixation", Map.of(
                "attack", "Attacker forces victim to use a known session ID before login. " +
                    "After login, attacker reuses that ID to hijack the authenticated session.",
                "springDefault", "changeSessionId — changes session ID on login (prevents fixation)",
                "options", List.of("changeSessionId (default, safe)", "migrateSession", "newSession", "none (unsafe)"),
                "config", ".sessionManagement(s -> s.sessionFixation(f -> f.changeSessionId()))"
            ),
            "concurrentSessions", Map.of(
                "use", "Limit sessions per user (e.g., max 1 session — forces re-login on new device)",
                "config", ".sessionManagement(s -> s.maximumSessions(1).maxSessionsPreventsLogin(false))",
                "maxSessionsPreventsLogin", "true = block new login when max reached; false = expire oldest session",
                "requires", "Spring Session or HttpSessionEventPublisher bean for tracking"
            ),
            "statelessNote", "This module uses STATELESS sessions for JWT. Session management " +
                "concepts apply to traditional form-login/session-based apps (Module 1).",
            "springSession", Map.of(
                "purpose", "Externalizes session storage (Redis, JDBC) for clustered deployments",
                "dependency", "spring-session-data-redis or spring-session-jdbc",
                "benefit", "Session sharing across multiple server instances"
            )
        ));
    }

    @GetMapping("/acl")
    @Operation(summary = "ACL (Access Control Lists) — domain object security")
    public ResponseEntity<?> aclGuide() {
        var guide = new java.util.LinkedHashMap<String, Object>();
        guide.put("concept", "ACL — Access Control Lists");
        guide.put("purpose", "Fine-grained permission control per domain object per user, " +
            "beyond role-based access (RBAC).");
        guide.put("example", "Document 123: Alice can READ, Bob can READ+WRITE, Carol is OWNER (READ+WRITE+DELETE)");
        guide.put("whenToUse", "When roles alone are insufficient — permissions depend on which specific object " +
            "and which user, not just what type of resource.");
        guide.put("springAclTables", List.of(
            "acl_class — maps Java class name to numeric ID",
            "acl_sid — maps principal/role to numeric ID (SID = Security Identity)",
            "acl_object_identity — maps each domain object instance to class + object ID",
            "acl_entry — the actual permission entries: who can do what to which object"
        ));
        guide.put("permissions", List.of("READ (1)", "WRITE (2)", "CREATE (4)", "DELETE (8)", "ADMINISTRATION (16)"));
        guide.put("annotations", List.of(
            "@PreAuthorize(\"hasPermission(#doc, 'READ')\")",
            "@PostAuthorize(\"hasPermission(returnObject, 'READ')\")"
        ));
        guide.put("dependencies", List.of(
            "spring-security-acl",
            "spring-security-config",
            "EhCache or similar for ACL caching"
        ));
        guide.put("configuration", List.of(
            "AclService bean (JdbcMutableAclService)",
            "AclAuthorizationStrategy bean",
            "PermissionGrantingStrategy bean",
            "MethodSecurityExpressionHandler with ACL support"
        ));
        guide.put("tradeoffs", Map.of(
            "pros", List.of("Very fine-grained", "Handles complex permission models"),
            "cons", List.of("Complex setup", "DB schema overhead",
                "Performance: cache ACLs aggressively", "Overkill for simple RBAC scenarios")
        ));
        guide.put("alternatives", List.of(
            "Custom @PostAuthorize with owner field check",
            "Attribute-Based Access Control (ABAC) with Spring Security SpEL",
            "OPA (Open Policy Agent) for policy-as-code"
        ));
        return ResponseEntity.ok(guide);
    }
}
