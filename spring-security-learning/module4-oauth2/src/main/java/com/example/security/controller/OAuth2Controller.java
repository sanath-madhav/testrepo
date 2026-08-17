package com.example.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

@Controller
public class OAuth2Controller {

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication, Model model) {
        if (authentication.getPrincipal() instanceof OAuth2User oAuth2User) {
            model.addAttribute("name", oAuth2User.getAttribute("name"));
            model.addAttribute("email", oAuth2User.getAttribute("email"));
            model.addAttribute("picture", oAuth2User.getAttribute("picture"));
            model.addAttribute("attributes", oAuth2User.getAttributes());
        }
        model.addAttribute("authorities", authentication.getAuthorities());
        return "dashboard";
    }

    /**
     * Demonstrates accessing the OAuth2 access token to call provider APIs.
     * @RegisteredOAuth2AuthorizedClient injects the OAuth2AuthorizedClient
     * which contains the access token for the registered provider.
     */
    @GetMapping("/api/oauth2-token")
    @ResponseBody
    public Map<String, String> getTokenInfo(
            @RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient client) {
        return Map.of(
            "tokenType", client.getAccessToken().getTokenType().getValue(),
            "scopes", client.getAccessToken().getScopes().toString(),
            "expiresAt", client.getAccessToken().getExpiresAt().toString()
        );
    }
}
