package com.example.security.config;

import com.example.security.service.CustomOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * CONCEPT: OAuth2 / OpenID Connect (OIDC) Authentication
 *
 * OAuth2 is an AUTHORIZATION framework, not an authentication protocol.
 * OpenID Connect (OIDC) is an AUTHENTICATION layer built on top of OAuth2.
 *
 * Key Roles:
 * ┌──────────────────────────────────────────────────────────────┐
 * │ Resource Owner: The user (you)                               │
 * │ Client: Our Spring Boot app                                  │
 * │ Authorization Server: Google / GitHub / Okta / etc.         │
 * │ Resource Server: Google APIs / GitHub APIs / etc.            │
 * └──────────────────────────────────────────────────────────────┘
 *
 * OAuth2 Authorization Code Flow (most secure, for web apps):
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │ 1. User clicks "Login with Google"                                   │
 * │ 2. App redirects to Google's Authorization Endpoint                  │
 * │    GET /auth?response_type=code&client_id=...&redirect_uri=...       │
 * │    &scope=openid email profile&state=random_csrf_protection_value    │
 * │ 3. Google shows consent screen, user approves                        │
 * │ 4. Google redirects back to app with authorization code              │
 * │    GET /login/oauth2/code/google?code=abc&state=xyz                  │
 * │ 5. App exchanges code for tokens (server-to-server, secure)          │
 * │    POST /token {code, client_id, client_secret, redirect_uri}        │
 * │    Response: {access_token, id_token, refresh_token}                 │
 * │ 6. App uses id_token (JWT) to get user info                          │
 * │ 7. App creates local session / returns JWT to client                 │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Spring Security handles steps 2-6 automatically!
 * We only need to configure client credentials and customize user mapping.
 *
 * Why Authorization Code Flow?
 * - Code is short-lived (single use)
 * - Tokens exchanged server-to-server (client_secret stays server-side)
 * - Access tokens never exposed in browser URL/history
 *
 * PKCE (Proof Key for Code Exchange) for public clients (SPA/mobile):
 * - code_verifier: random string
 * - code_challenge: SHA256(code_verifier)
 * - Prevents authorization code interception attacks
 */
@Configuration
@EnableWebSecurity
public class OAuth2SecurityConfig {

    private final CustomOAuth2UserService oAuth2UserService;

    public OAuth2SecurityConfig(CustomOAuth2UserService oAuth2UserService) {
        this.oAuth2UserService = oAuth2UserService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/error").permitAll()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                // Spring auto-registers: /oauth2/authorization/{registrationId}
                // e.g., /oauth2/authorization/google -> redirects to Google
                .loginPage("/login")

                // Callback URL where provider redirects with code
                // Default: /login/oauth2/code/{registrationId}
                // .redirectionEndpoint(r -> r.baseUri("/login/oauth2/code/*"))

                // Custom service to process OAuth2 user info
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(oAuth2UserService)
                )

                // Where to go after successful OAuth2 login
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=oauth2_error")
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            );

        return http.build();
    }
}
