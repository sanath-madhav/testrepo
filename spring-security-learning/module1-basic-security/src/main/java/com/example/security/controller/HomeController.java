package com.example.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Demonstrates how to access the authenticated user's information
 * from the SecurityContext inside a controller.
 *
 * SecurityContextHolder holds the SecurityContext which contains the Authentication.
 * Authentication contains:
 * - Principal: the logged-in user (UserDetails object)
 * - Credentials: password (cleared after authentication for security)
 * - Authorities: granted permissions
 * - isAuthenticated(): whether the user is authenticated
 */
@Controller
public class HomeController {

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("message", "Welcome to Spring Security Learning!");
        return "home";
    }

    @GetMapping("/home")
    public String publicHome(Model model) {
        model.addAttribute("title", "Public Home");
        return "home";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication, Model model) {
        // Authentication object injected directly by Spring MVC
        model.addAttribute("username", authentication.getName());
        model.addAttribute("roles", authentication.getAuthorities());
        return "dashboard";
    }

    @GetMapping("/admin")
    public String adminPage(Model model) {
        // Can also get Authentication from SecurityContextHolder
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("username", auth.getName());
        return "admin";
    }

    @GetMapping("/manager")
    public String managerPage(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("username", auth.getName());
        return "manager";
    }
}
