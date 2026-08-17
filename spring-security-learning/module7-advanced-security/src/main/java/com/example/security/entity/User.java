package com.example.security.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * User entity supporting:
 * - Role-based access (ROLE_USER, ROLE_MANAGER, ROLE_ADMIN)
 * - Account lockout for brute force protection
 * - Password policy fields (last changed, history)
 * - Persistent remember-me via username
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<String> roles = new HashSet<>();

    private boolean accountLocked = false;
    private int failedLoginAttempts = 0;
    private Instant lockoutTime;

    private Instant passwordChangedAt = Instant.now();

    protected User() {}

    public User(String username, String password, Set<String> roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public Set<String> getRoles() { return roles; }
    public boolean isAccountLocked() { return accountLocked; }
    public int getFailedLoginAttempts() { return failedLoginAttempts; }
    public Instant getLockoutTime() { return lockoutTime; }
    public Instant getPasswordChangedAt() { return passwordChangedAt; }

    public void incrementFailedAttempts() { this.failedLoginAttempts++; }
    public void resetFailedAttempts() { this.failedLoginAttempts = 0; }
    public void lock(Instant lockoutTime) {
        this.accountLocked = true;
        this.lockoutTime = lockoutTime;
    }
    public void unlock() {
        this.accountLocked = false;
        this.failedLoginAttempts = 0;
        this.lockoutTime = null;
    }
    public void setPassword(String password) {
        this.password = password;
        this.passwordChangedAt = Instant.now();
    }
}
