package com.example.security.filter;

import com.example.security.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * CONCEPT: JWT Authentication Filter
 *
 * OncePerRequestFilter guarantees this filter runs exactly once per request.
 *
 * JWT Authentication Flow per request:
 * ┌──────────────────────────────────────────────────────────────────┐
 * │ Incoming Request                                                  │
 * │      │                                                            │
 * │      ▼                                                            │
 * │ JwtAuthenticationFilter.doFilterInternal()                        │
 * │      │                                                            │
 * │      ├─ Extract "Authorization" header                            │
 * │      ├─ Check "Bearer " prefix                                    │
 * │      ├─ Extract JWT token                                         │
 * │      ├─ Extract username from token (JwtUtil.extractUsername)     │
 * │      ├─ Check SecurityContext is empty (not already authenticated) │
 * │      ├─ Load UserDetails from UserDetailsService                  │
 * │      ├─ Validate token (signature + expiry + username match)      │
 * │      ├─ Create UsernamePasswordAuthenticationToken (authenticated) │
 * │      ├─ Set authentication details (IP, session ID)               │
 * │      ├─ Store in SecurityContextHolder                            │
 * │      └─ Continue filter chain                                     │
 * │                                                                   │
 * │ If token missing/invalid: continue filter chain WITHOUT auth      │
 * │ (the request will be rejected by SecurityFilterChain rules)       │
 * └──────────────────────────────────────────────────────────────────┘
 *
 * WHY check SecurityContext.getAuthentication() == null?
 * Prevents re-authentication if another filter already set it.
 * E.g., @WithMockUser in tests already populates SecurityContext.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // If no Authorization header or not a Bearer token, skip this filter
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract the JWT token (remove "Bearer " prefix)
        final String jwt = authHeader.substring(7);
        final String username;

        try {
            username = jwtUtil.extractUsername(jwt);
        } catch (Exception e) {
            // Invalid token structure — let the request proceed unauthenticated
            filterChain.doFilter(request, response);
            return;
        }

        // Only authenticate if username extracted AND SecurityContext is empty
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (jwtUtil.validateToken(jwt, userDetails)) {
                // Create authenticated token
                UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // credentials set to null (not needed after authentication)
                        userDetails.getAuthorities()
                    );

                // Attach request details (IP, session info) to authentication
                authToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Store authentication in SecurityContext for this request
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
