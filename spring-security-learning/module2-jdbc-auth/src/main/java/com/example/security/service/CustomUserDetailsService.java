package com.example.security.service;

import com.example.security.entity.AppUser;
import com.example.security.entity.Role;
import com.example.security.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * CONCEPT: Custom UserDetailsService
 *
 * UserDetailsService is the central interface in Spring Security's authentication.
 * It has ONE method: loadUserByUsername(String username) -> UserDetails
 *
 * Spring Security calls this when:
 * 1. A user submits login credentials
 * 2. A "remember me" token is validated
 * 3. A pre-authenticated token is verified
 *
 * The returned UserDetails object contains:
 * - username (used for authentication)
 * - password (compared against submitted password using PasswordEncoder)
 * - authorities (roles/permissions granted to user)
 * - account status flags (locked, expired, enabled)
 *
 * Flow:
 * LoginRequest -> AuthenticationFilter -> AuthenticationManager
 *   -> DaoAuthenticationProvider.loadUserByUsername()
 *   -> YOUR CustomUserDetailsService.loadUserByUsername()
 *   -> DB query -> UserDetails -> password comparison -> Authentication
 */
@Service
@Transactional(readOnly = true)
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(
                "User not found: " + username
                // Security note: don't reveal whether username exists vs wrong password
                // Use a generic message in production: "Invalid credentials"
            ));

        // Convert domain roles to Spring Security GrantedAuthority objects
        Set<GrantedAuthority> authorities = mapRolesToAuthorities(appUser.getRoles());

        // Build and return Spring Security's UserDetails
        return User.builder()
            .username(appUser.getUsername())
            .password(appUser.getPassword()) // already BCrypt encoded in DB
            .authorities(authorities)
            .accountExpired(!appUser.isAccountNonExpired())
            .accountLocked(!appUser.isAccountNonLocked())
            .credentialsExpired(!appUser.isCredentialsNonExpired())
            .disabled(!appUser.isEnabled())
            .build();
    }

    private Set<GrantedAuthority> mapRolesToAuthorities(Set<Role> roles) {
        return roles.stream()
            .map(role -> new SimpleGrantedAuthority(role.getName()))
            .collect(Collectors.toSet());
    }
}
