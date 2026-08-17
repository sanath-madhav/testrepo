package com.example.security.entity;

import jakarta.persistence.*;

/**
 * Role entity representing a security role.
 * Spring Security expects role names prefixed with "ROLE_"
 * e.g., ROLE_USER, ROLE_ADMIN, ROLE_MANAGER
 */
@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name; // e.g., ROLE_USER, ROLE_ADMIN

    public Role() {}
    public Role(String name) { this.name = name; }

    public Long getId() { return id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    @Override
    public String toString() { return name; }
}
