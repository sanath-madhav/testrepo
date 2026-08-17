package com.example.security.config;

import com.example.security.filter.JwtAuthenticationFilter;
import com.example.security.service.JwtUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * CONCEPT: JWT Security Configuration
 *
 * Key architectural decisions for JWT-based security:
 *
 * 1. STATELESS session: no HTTP session created or used
 *    - Server doesn't remember authenticated users between requests
 *    - JWT in each request IS the session state
 *    - Enables horizontal scaling without session replication
 *
 * 2. Custom JwtAuthenticationFilter added BEFORE UsernamePasswordAuthenticationFilter
 *    - Intercepts every request, extracts JWT, validates, sets SecurityContext
 *    - UsernamePasswordAuthenticationFilter handles form login (we use /auth/login instead)
 *
 * 3. CSRF disabled: JWT is immune to CSRF
 *    - CSRF exploits: browser auto-sends cookies with cross-site requests
 *    - JWT in Authorization header is NOT auto-sent by browsers
 *    - Therefore CSRF protection is unnecessary for pure JWT APIs
 *
 * 4. No form login: authentication handled by /auth/login endpoint
 *
 * Filter Order in Spring Security:
 * ... -> JwtAuthenticationFilter -> UsernamePasswordAuthenticationFilter -> ...
 *                                   (usually bypassed for JWT APIs)
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final JwtUserDetailsService userDetailsService;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthFilter,
                          JwtUserDetailsService userDetailsService) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Safe: JWT in header, not cookie
            .authorizeHttpRequests(auth -> auth
                // Public: auth endpoints, Swagger
                .requestMatchers("/auth/**").permitAll()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                .requestMatchers("/h2-console/**").permitAll()
                // Admin-only
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                // Everything else requires JWT
                .anyRequest().authenticated()
            )
            // Return 401 (not 403) for unauthenticated requests
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(401);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Authentication required\"}");
                })
            )
            // Stateless: no session, no cookies
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authenticationProvider(authenticationProvider())
            // Add JWT filter before Spring's default authentication filter
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .headers(h -> h.frameOptions(f -> f.sameOrigin()));

        return http.build();
    }
}
