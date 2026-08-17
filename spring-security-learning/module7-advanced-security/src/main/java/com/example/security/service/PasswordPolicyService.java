package com.example.security.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Password policy enforcement.
 *
 * Typical enterprise password policy requirements:
 * - Minimum length (NIST SP 800-63B recommends at least 8, better 12+)
 * - Maximum length (avoid DoS via very long bcrypt inputs — cap at 72 bytes)
 * - Complexity: uppercase, lowercase, digit, special character
 * - No common passwords (in production: check against Have I Been Pwned API)
 * - No username as password
 * - No sequential characters (aaa, 123)
 *
 * NIST 800-63B modern guidance (2024):
 * - Long passphrases are better than complexity requirements
 * - Don't require periodic rotations (they cause weaker passwords)
 * - Do check against known breach databases
 * - Do check against a blocklist of common passwords
 */
@Service
public class PasswordPolicyService {

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 72; // bcrypt processes max 72 bytes
    private static final Pattern HAS_UPPERCASE = Pattern.compile("[A-Z]");
    private static final Pattern HAS_LOWERCASE = Pattern.compile("[a-z]");
    private static final Pattern HAS_DIGIT = Pattern.compile("\\d");
    private static final Pattern HAS_SPECIAL = Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]");

    private static final List<String> COMMON_PASSWORDS = List.of(
        "password", "password123", "123456", "12345678", "qwerty",
        "abc123", "letmein", "monkey", "welcome", "admin",
        "login", "pass", "master", "hello", "dragon"
    );

    public record PolicyResult(boolean valid, List<String> violations) {}

    public PolicyResult validate(String password, String username) {
        List<String> violations = new ArrayList<>();

        if (password == null || password.length() < MIN_LENGTH) {
            violations.add("Password must be at least " + MIN_LENGTH + " characters long");
        }
        if (password != null && password.length() > MAX_LENGTH) {
            violations.add("Password must not exceed " + MAX_LENGTH + " characters");
        }
        if (password != null && !HAS_UPPERCASE.matcher(password).find()) {
            violations.add("Password must contain at least one uppercase letter");
        }
        if (password != null && !HAS_LOWERCASE.matcher(password).find()) {
            violations.add("Password must contain at least one lowercase letter");
        }
        if (password != null && !HAS_DIGIT.matcher(password).find()) {
            violations.add("Password must contain at least one digit");
        }
        if (password != null && !HAS_SPECIAL.matcher(password).find()) {
            violations.add("Password must contain at least one special character");
        }
        if (password != null && username != null
                && password.toLowerCase().contains(username.toLowerCase())) {
            violations.add("Password must not contain your username");
        }
        if (password != null) {
            String lower = password.toLowerCase();
            for (String common : COMMON_PASSWORDS) {
                if (lower.equals(common)) {
                    violations.add("Password is too common — choose a unique passphrase");
                    break;
                }
            }
        }
        if (password != null && hasSequentialChars(password)) {
            violations.add("Password must not contain sequential characters (aaa, 123)");
        }

        return new PolicyResult(violations.isEmpty(), violations);
    }

    private boolean hasSequentialChars(String password) {
        for (int i = 0; i < password.length() - 2; i++) {
            char c1 = password.charAt(i);
            char c2 = password.charAt(i + 1);
            char c3 = password.charAt(i + 2);
            // All same character or sequential ascending/descending
            if (c1 == c2 && c2 == c3) return true;
            if (c2 == c1 + 1 && c3 == c2 + 1) return true;
            if (c2 == c1 - 1 && c3 == c2 - 1) return true;
        }
        return false;
    }

    public int calculateStrength(String password) {
        if (password == null || password.isEmpty()) return 0;
        int score = 0;
        if (password.length() >= 8) score++;
        if (password.length() >= 12) score++;
        if (password.length() >= 16) score++;
        if (HAS_UPPERCASE.matcher(password).find()) score++;
        if (HAS_LOWERCASE.matcher(password).find()) score++;
        if (HAS_DIGIT.matcher(password).find()) score++;
        if (HAS_SPECIAL.matcher(password).find()) score++;
        return Math.min(score, 5); // 0–5 scale
    }
}
