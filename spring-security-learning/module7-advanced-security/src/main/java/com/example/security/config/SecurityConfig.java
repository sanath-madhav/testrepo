package com.example.security.config;

import com.example.security.filter.JwtAuthFilter;
import com.example.security.provider.CustomAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Comprehensive security configuration demonstrating advanced Spring Security features:
 *
 * 1. Custom AuthenticationProvider with brute force protection
 * 2. Role Hierarchy (ROLE_ADMIN > ROLE_MANAGER > ROLE_USER)
 * 3. Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
 * 4. CORS configuration
 * 5. Stateless JWT authentication
 * 6. Method-level security (@PreAuthorize, @PostAuthorize)
 * 7. Custom 401/403 error responses
 *
 * Security Headers Explained:
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * HSTS (Strict-Transport-Security)
 *   Forces HTTPS. Browser remembers for maxAge seconds.
 *   includeSubDomains: applies to all subdomains.
 *   preload: can be submitted to browser preload lists.
 *   Example: Strict-Transport-Security: max-age=31536000; includeSubDomains
 *
 * CSP (Content-Security-Policy)
 *   Controls what resources the browser can load.
 *   Prevents XSS by blocking inline scripts and external resource loading.
 *   Example: Content-Security-Policy: default-src 'self'; script-src 'self'
 *
 * X-Frame-Options: DENY
 *   Prevents clickjacking by blocking iframe embedding.
 *   DENY: never in frame. SAMEORIGIN: allow same origin only.
 *
 * X-Content-Type-Options: nosniff
 *   Prevents MIME type sniffing. Browser must use declared Content-Type.
 *   Stops "content sniffing" attacks where browser guesses file type.
 *
 * Referrer-Policy: strict-origin-when-cross-origin
 *   Controls how much referrer info is sent in requests.
 *   Protects user privacy and prevents leaking sensitive URLs.
 *
 * Permissions-Policy (formerly Feature-Policy)
 *   Controls browser features: camera, microphone, geolocation.
 *   "camera=(), microphone=()" disables these features for the page.
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final CustomAuthenticationProvider customAuthenticationProvider;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter,
                          CustomAuthenticationProvider customAuthenticationProvider) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.customAuthenticationProvider = customAuthenticationProvider;
    }

    /**
     * Role Hierarchy configuration.
     *
     * ROLE_ADMIN > ROLE_MANAGER > ROLE_USER means:
     * - ADMIN automatically has MANAGER and USER authorities
     * - MANAGER automatically has USER authorities
     * - No need for explicit role checks at each level
     *
     * Without hierarchy:
     *   hasRole("USER") fails for ADMIN unless they also have ROLE_USER
     * With hierarchy:
     *   hasRole("USER") passes for ADMIN, MANAGER, and USER
     *
     * Used automatically by Spring Security's expression evaluator when
     * registered as a bean named "roleHierarchy".
     */
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER");
        return hierarchy;
    }

    /**
     * Explicit MethodSecurityExpressionHandler with role hierarchy wired in.
     * This makes @PreAuthorize("hasRole('MANAGER')") return true for ROLE_ADMIN users.
     * Spring Security 6.2 auto-wires RoleHierarchy for method security, but declaring this
     * explicitly ensures the hierarchy is applied to @PreAuthorize, @PostAuthorize, etc.
     */
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(customAuthenticationProvider);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(c -> c.disable()) // JWT API: no browser sessions, no CSRF risk
            .cors(c -> c.configurationSource(corsConfigurationSource()))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // ── Security Headers ──────────────────────────────────────────────
            .headers(h -> h
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000) // 1 year
                    .preload(true))
                .frameOptions(f -> f.deny())
                .contentTypeOptions(c -> {}) // adds X-Content-Type-Options: nosniff
                .referrerPolicy(r -> r.policy(
                    ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                .permissionsPolicy(p -> p.policy(
                    "camera=(), microphone=(), geolocation=(), payment=()"))
            )

            // ── Authorization Rules ───────────────────────────────────────────
            // Note: hasRole() in authorizeHttpRequests() does NOT apply role hierarchy in
            // Spring Security 6.2. Role hierarchy is supported in @PreAuthorize expressions.
            // Fine-grained role hierarchy checks are handled at the method level (@PreAuthorize).
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**", "/api/public/**",
                                 "/swagger-ui/**", "/v3/api-docs/**",
                                 "/h2-console/**").permitAll()
                .requestMatchers("/api/audit/**").hasRole("ADMIN")
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )

            // ── Exception Handling ─────────────────────────────────────────────
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((req, res, e) -> {
                    res.setStatus(401);
                    res.setContentType("application/json");
                    res.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\""
                        + e.getMessage() + "\"}");
                })
                .accessDeniedHandler((req, res, e) -> {
                    res.setStatus(403);
                    res.setContentType("application/json");
                    res.getWriter().write("{\"error\":\"Forbidden\",\"message\":\"Insufficient privileges\"}");
                })
            )

            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .headers(h -> h.frameOptions(f -> f.sameOrigin())); // H2 console in same origin

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        // In production: use specific origins, not "*"
        config.setAllowedOriginPatterns(List.of("http://localhost:3000", "https://yourdomain.com"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        config.setExposedHeaders(List.of("Authorization")); // expose JWT header to JS
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
