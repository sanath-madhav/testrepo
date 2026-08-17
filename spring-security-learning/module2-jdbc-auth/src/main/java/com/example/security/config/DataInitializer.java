package com.example.security.config;

import com.example.security.entity.AppUser;
import com.example.security.entity.Role;
import com.example.security.repository.RoleRepository;
import com.example.security.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Seeds the database with initial roles and users on startup.
 * In production, use Flyway or Liquibase for database migrations.
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        // Create roles
        Role roleUser = roleRepository.findByName("ROLE_USER")
            .orElseGet(() -> roleRepository.save(new Role("ROLE_USER")));
        Role roleAdmin = roleRepository.findByName("ROLE_ADMIN")
            .orElseGet(() -> roleRepository.save(new Role("ROLE_ADMIN")));

        // Create users (only if they don't exist)
        if (!userRepository.existsByUsername("dbuser")) {
            userRepository.save(new AppUser(
                "dbuser",
                passwordEncoder.encode("password"),
                Set.of(roleUser)
            ));
        }

        if (!userRepository.existsByUsername("dbadmin")) {
            userRepository.save(new AppUser(
                "dbadmin",
                passwordEncoder.encode("admin123"),
                Set.of(roleUser, roleAdmin)
            ));
        }
    }
}
