package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * CONCEPT: In-Memory Authentication + Form Login
 *
 * Spring Security Authentication Flow:
 * 1. HTTP Request arrives at the server
 * 2. SecurityFilterChain intercepts the request
 * 3. UsernamePasswordAuthenticationFilter extracts credentials
 * 4. AuthenticationManager delegates to AuthenticationProvider
 * 5. AuthenticationProvider uses UserDetailsService to load user
 * 6. Password is verified using PasswordEncoder
 * 7. On success: SecurityContext is populated with Authentication
 * 8. On failure: AuthenticationFailureHandler is invoked
 *
 * Key Components:
 * - SecurityFilterChain: Chain of servlet filters that enforce security
 * - UserDetailsService: Loads user-specific data (username, password, roles)
 * - PasswordEncoder: Encodes and verifies passwords (BCrypt recommended)
 * - AuthenticationManager: Orchestrates the authentication process
 */
@Configuration
@EnableWebSecurity
@Profile("inmemory")
public class InMemorySecurityConfig {

    /**
     * BCryptPasswordEncoder is the recommended password encoder.
     * BCrypt uses a work factor (strength) to slow down brute-force attacks.
     * Default strength is 10, which means 2^10 = 1024 iterations.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // strength 12 for production
    }

    /**
     * InMemoryUserDetailsManager stores users in memory.
     * Suitable for: testing, development, small applications.
     * NOT suitable for production (no persistence, no user management).
     *
     * UserDetails contains:
     * - username: unique identifier
     * - password: encoded password
     * - authorities: granted permissions (roles)
     * - accountNonExpired, accountNonLocked, credentialsNonExpired, enabled: account status flags
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        UserDetails user = User.builder()
                .username("user")
                .password(encoder.encode("password"))
                .roles("USER")          // internally stored as ROLE_USER
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(encoder.encode("admin123"))
                .roles("USER", "ADMIN") // ROLE_USER and ROLE_ADMIN
                .build();

        UserDetails manager = User.builder()
                .username("manager")
                .password(encoder.encode("manager123"))
                .roles("MANAGER")
                .authorities("READ", "WRITE", "ROLE_MANAGER") // mixed authorities
                .build();

        return new InMemoryUserDetailsManager(user, admin, manager);
    }

    /**
     * SecurityFilterChain defines the security rules for HTTP requests.
     *
     * Request matching is evaluated TOP-DOWN — order matters!
     * - More specific matchers MUST come before general ones
     * - requestMatchers("/admin/**").hasRole("ADMIN") before anyRequest().authenticated()
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // Public endpoints - no authentication required
                .requestMatchers("/", "/home", "/public/**").permitAll()
                // Swagger UI - public for learning
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                // Admin-only endpoints
                .requestMatchers("/admin/**").hasRole("ADMIN")
                // Manager or Admin endpoints
                .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                // Custom login page URL (GET /login shows the form)
                .loginPage("/login")
                // POST /login processes credentials (default)
                .loginProcessingUrl("/login")
                // Where to go after successful login
                .defaultSuccessUrl("/dashboard", true)
                // Where to go after failed login
                .failureUrl("/login?error=true")
                // Allow unauthenticated access to login page
                .permitAll()
            )
            .logout(logout -> logout
                // POST /logout triggers logout
                .logoutUrl("/logout")
                // Where to redirect after logout
                .logoutSuccessUrl("/login?logout=true")
                // Invalidate HTTP session on logout
                .invalidateHttpSession(true)
                // Delete the remember-me cookie
                .deleteCookies("JSESSIONID", "remember-me")
            )
            // Remember-me: keeps user logged in across sessions
            .rememberMe(remember -> remember
                .key("uniqueAndSecretKey")  // HMAC signing key
                .tokenValiditySeconds(86400) // 24 hours
            );

        return http.build();
    }
}
