package com.example.security.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * CONCEPT: Custom OAuth2UserService
 *
 * After receiving user info from the OAuth2 provider, Spring calls this service.
 * This is where you:
 * 1. Extract user attributes from the provider response
 * 2. Map provider attributes to your local user model
 * 3. Create or update local user record (optional)
 * 4. Assign local roles/authorities
 *
 * Different providers return different attribute keys:
 * - Google: "sub" (unique ID), "email", "name", "picture"
 * - GitHub: "id", "login", "email", "avatar_url"
 * - Facebook: "id", "name", "email"
 *
 * OAuth2User vs OidcUser:
 * - OAuth2User: standard OAuth2 (just access token)
 * - OidcUser: OpenID Connect (access token + id_token with user claims)
 *   OIDC is preferred as it provides standardized user info in the id_token
 */
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // Let the default service fetch user info from the provider
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // Determine which provider we're dealing with
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // Get the attribute name that serves as the unique identifier
        String userNameAttributeName = userRequest.getClientRegistration()
            .getProviderDetails()
            .getUserInfoEndpoint()
            .getUserNameAttributeName();

        Map<String, Object> attributes = oAuth2User.getAttributes();

        // Log for learning purposes
        System.out.println("OAuth2 Provider: " + registrationId);
        System.out.println("User attributes: " + attributes);

        // Assign roles based on provider or email domain (business logic)
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        // Example: make users from a specific domain admins
        String email = (String) attributes.get("email");
        if (email != null && email.endsWith("@admin-domain.com")) {
            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }

        // Here you could also:
        // 1. Look up or create user in your database
        // 2. Sync profile information
        // 3. Apply additional role mappings

        return new DefaultOAuth2User(authorities, attributes, userNameAttributeName);
    }
}
