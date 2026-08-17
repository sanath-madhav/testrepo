package com.example.security.provider;

import com.example.security.service.BruteForceProtectionService;
import com.example.security.service.UserDetailsServiceImpl;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Custom AuthenticationProvider — plugs into Spring Security's ProviderManager.
 *
 * Why implement a custom AuthenticationProvider?
 * 1. Add extra checks before/after authentication (e.g., brute force protection)
 * 2. Support custom token types beyond UsernamePasswordAuthenticationToken
 *    (e.g., OtpAuthenticationToken, ApiKeyAuthenticationToken)
 * 3. Integrate with external identity sources (LDAP, AD, external API)
 * 4. Add custom business rules (e.g., "only company email domains allowed")
 *
 * How ProviderManager works:
 * - AuthenticationManager is implemented by ProviderManager
 * - ProviderManager holds a list of AuthenticationProvider instances
 * - It delegates to the first provider that supports() the token type
 * - If no provider succeeds, throws ProviderNotFoundException
 *
 * supports() is critical: tells ProviderManager which token types this
 * provider can handle. Without it, your provider is skipped entirely.
 */
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsServiceImpl userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final BruteForceProtectionService bruteForceProtectionService;

    public CustomAuthenticationProvider(UserDetailsServiceImpl userDetailsService,
                                        PasswordEncoder passwordEncoder,
                                        BruteForceProtectionService bruteForceProtectionService) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.bruteForceProtectionService = bruteForceProtectionService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        // Step 1: Check brute force lockout BEFORE loading user details
        // This prevents user enumeration via timing: locked accounts fail fast
        if (bruteForceProtectionService.isLocked(username)) {
            throw new LockedException("Account is temporarily locked due to too many failed attempts. "
                + "Please try again later.");
        }

        // Step 2: Load user — throws UsernameNotFoundException if not found
        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException ex) {
            // Record failure even for unknown users — prevents timing attack revealing usernames
            bruteForceProtectionService.recordFailedAttempt(username);
            // Use generic message — don't reveal that the user doesn't exist
            throw new BadCredentialsException("Invalid username or password");
        }

        // Step 3: Check account locked (might have been locked via UserDetails too)
        if (!userDetails.isAccountNonLocked()) {
            throw new LockedException("Account is locked");
        }

        // Step 4: Verify password
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            bruteForceProtectionService.recordFailedAttempt(username);
            int remaining = bruteForceProtectionService.getRemainingAttempts(username);
            throw new BadCredentialsException(
                "Invalid username or password. Attempts remaining before lockout: " + remaining);
        }

        // Step 5: Record successful login — reset failure counter
        bruteForceProtectionService.recordSuccessfulLogin(username);

        // Step 6: Return authenticated token with authorities
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // This provider handles username/password authentication
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
