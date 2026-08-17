package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * CONCEPT: Method-Level Security
 *
 * @EnableMethodSecurity enables three types of method security:
 *
 * 1. @PreAuthorize / @PostAuthorize (Spring's expression-based, recommended)
 * 2. @Secured (role-based, simpler, Spring-proprietary)
 * 3. @RolesAllowed (JSR-250 standard annotation)
 *
 * Method security uses AOP (Aspect-Oriented Programming):
 * - A security proxy wraps the bean
 * - Proxy intercepts method calls
 * - Evaluates SpEL expression BEFORE (@Pre) or AFTER (@Post) method execution
 * - Throws AccessDeniedException if check fails
 *
 * IMPORTANT: Method security only works when calling across Spring bean boundaries!
 * - Calling a @PreAuthorize method on SAME bean = NO proxy = NO security check
 * - Solution: inject self or use ApplicationContext.getBean()
 *
 * SpEL Expressions available in @PreAuthorize:
 * - hasRole('ADMIN')        - checks ROLE_ADMIN
 * - hasAnyRole(...)         - checks any of the roles
 * - hasAuthority('READ')    - exact authority match
 * - isAuthenticated()       - any logged-in user
 * - isAnonymous()           - not logged in
 * - principal               - the Authentication.getPrincipal()
 * - authentication          - the full Authentication object
 * - #paramName              - method parameter value
 * - returnObject            - return value (in @PostAuthorize)
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(
    prePostEnabled = true,   // enables @PreAuthorize and @PostAuthorize
    securedEnabled = true,   // enables @Secured
    jsr250Enabled = true     // enables @RolesAllowed
)
public class MethodSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        return new InMemoryUserDetailsManager(
            User.builder().username("user").password(encoder.encode("pass")).roles("USER").build(),
            User.builder().username("admin").password(encoder.encode("pass")).roles("ADMIN").build(),
            User.builder().username("manager").password(encoder.encode("pass"))
                .roles("MANAGER").authorities("ROLE_MANAGER", "READ", "WRITE").build()
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                .anyRequest().authenticated()
            )
            .httpBasic(b -> b.realmName("Method Security Demo"))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable())
            // CORS configuration for cross-origin API access
            .cors(cors -> cors.configurationSource(corsConfigurationSource()));

        return http.build();
    }

    /**
     * CONCEPT: CORS (Cross-Origin Resource Sharing)
     *
     * Browser security: same-origin policy blocks cross-origin AJAX requests.
     * CORS lets the server tell browsers which origins are allowed.
     *
     * CORS Headers:
     * - Access-Control-Allow-Origin: which origins can make requests
     * - Access-Control-Allow-Methods: which HTTP methods are allowed
     * - Access-Control-Allow-Headers: which request headers are allowed
     * - Access-Control-Allow-Credentials: whether cookies/auth can be sent
     *
     * Preflight Request (OPTIONS method):
     * - Browser sends OPTIONS before complex cross-origin requests
     * - Server must respond with appropriate CORS headers
     * - Spring Security handles this automatically with proper CORS config
     *
     * WARNING: Access-Control-Allow-Origin: * with Allow-Credentials: true is INVALID.
     * Must specify exact origins when credentials are involved.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        // Allowed origins (in production: specific domains only)
        config.setAllowedOrigins(List.of(
            "http://localhost:3000",  // React dev server
            "http://localhost:4200",  // Angular dev server
            "https://your-frontend.com"
        ));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        config.setAllowCredentials(true); // Allow cookies / Authorization header
        config.setMaxAge(3600L); // Cache preflight response for 1 hour

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
