package com.example.security.config;

import com.example.security.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * CONCEPT: DaoAuthenticationProvider + Custom UserDetailsService
 *
 * DaoAuthenticationProvider is the default AuthenticationProvider used by Spring Security.
 * DAO = Data Access Object — it uses a UserDetailsService to access user data.
 *
 * Internal Authentication Flow:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │ 1. Client sends credentials (username + password)                   │
 * │ 2. UsernamePasswordAuthenticationFilter creates                     │
 * │    UsernamePasswordAuthenticationToken (unauthenticated)           │
 * │ 3. AuthenticationManager.authenticate() is called                  │
 * │ 4. ProviderManager iterates AuthenticationProviders                │
 * │ 5. DaoAuthenticationProvider.authenticate() is invoked             │
 * │    a. Calls userDetailsService.loadUserByUsername(username)        │
 * │    b. Calls passwordEncoder.matches(raw, encoded)                  │
 * │    c. Checks account status flags                                  │
 * │ 6. Returns UsernamePasswordAuthenticationToken (authenticated)     │
 * │ 7. SecurityContextHolder stores the Authentication                 │
 * └─────────────────────────────────────────────────────────────────────┘
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;

    public SecurityConfig(CustomUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * DaoAuthenticationProvider wires together:
     * - UserDetailsService: loads user data from database
     * - PasswordEncoder: verifies submitted password against stored hash
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        // Optional: hide UsernameNotFoundException (security best practice)
        provider.setHideUserNotFoundExceptions(true);
        return provider;
    }

    /**
     * AuthenticationManager is exposed as a Bean so it can be injected
     * into controllers or services that need to programmatically authenticate users.
     * Example: JWT login endpoint needs to call authenticate() manually.
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authenticationProvider(authenticationProvider())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/h2-console/**").permitAll()
                .requestMatchers("/api/register").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .httpBasic(basic -> basic.realmName("JDBC Auth Demo"))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable())
            // Allow H2 console in iframe (dev only)
            .headers(h -> h.frameOptions(f -> f.sameOrigin()));

        return http.build();
    }
}
