package com.example.security.config;

import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (!userRepository.existsByUsername("jwtuser")) {
            userRepository.save(new User(
                "jwtuser",
                passwordEncoder.encode("password"),
                Set.of("ROLE_USER")
            ));
        }
        if (!userRepository.existsByUsername("jwtadmin")) {
            userRepository.save(new User(
                "jwtadmin",
                passwordEncoder.encode("admin123"),
                Set.of("ROLE_USER", "ROLE_ADMIN")
            ));
        }
    }
}
