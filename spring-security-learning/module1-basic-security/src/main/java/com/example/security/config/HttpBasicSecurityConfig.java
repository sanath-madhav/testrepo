package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * CONCEPT: HTTP Basic Authentication
 *
 * HTTP Basic Auth Flow:
 * 1. Client sends request WITHOUT credentials
 * 2. Server responds with 401 Unauthorized + WWW-Authenticate: Basic realm="..."
 * 3. Client sends credentials as Base64(username:password) in Authorization header
 *    Authorization: Basic dXNlcjpwYXNzd29yZA==
 * 4. Server decodes and validates credentials on EVERY request
 *
 * Characteristics:
 * - Stateless: no session/cookie (credentials sent with every request)
 * - Simple: browser shows native credential dialog
 * - Insecure over HTTP (credentials are only Base64-encoded, NOT encrypted)
 * - Suitable for: REST APIs, microservices, machine-to-machine calls
 * - NOT suitable for: browser-based applications (no logout mechanism)
 *
 * Security Consideration: ALWAYS use HTTPS with Basic Auth
 */
@Configuration
@EnableWebSecurity
@Profile("httpbasic")
public class HttpBasicSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        return new InMemoryUserDetailsManager(
            User.builder()
                .username("api-user")
                .password(encoder.encode("api-pass"))
                .roles("USER")
                .build(),
            User.builder()
                .username("api-admin")
                .password(encoder.encode("api-admin-pass"))
                .roles("ADMIN")
                .build()
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .httpBasic(basic -> basic
                // Realm name shown in browser dialog
                .realmName("Spring Security Learning API")
            )
            // STATELESS: no session created or used
            // Each request must carry credentials
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // Disable CSRF for stateless APIs (no session = no CSRF vulnerability)
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
