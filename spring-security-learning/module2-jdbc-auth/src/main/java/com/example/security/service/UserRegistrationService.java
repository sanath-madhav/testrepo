package com.example.security.service;

import com.example.security.controller.RegistrationRequest;
import com.example.security.entity.AppUser;
import com.example.security.entity.Role;
import com.example.security.repository.RoleRepository;
import com.example.security.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

/**
 * Service for user registration with proper password encoding.
 *
 * CRITICAL SECURITY RULE: NEVER store plaintext passwords.
 * Always encode passwords BEFORE storing in the database.
 *
 * BCrypt characteristics:
 * - Adaptive hash function: work factor can increase over time
 * - Automatically generates and stores a salt
 * - Same plaintext = different hash every time (due to random salt)
 * - Computationally expensive by design (slow = hard to brute-force)
 */
@Service
@Transactional
public class UserRegistrationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserRegistrationService(UserRepository userRepository,
                                   RoleRepository roleRepository,
                                   PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public AppUser registerUser(RegistrationRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Username already taken: " + request.username());
        }

        Role userRole = roleRepository.findByName("ROLE_USER")
            .orElseThrow(() -> new RuntimeException("ROLE_USER not found in database"));

        AppUser newUser = new AppUser(
            request.username(),
            passwordEncoder.encode(request.password()), // ENCODE before saving
            Set.of(userRole)
        );

        return userRepository.save(newUser);
    }
}
