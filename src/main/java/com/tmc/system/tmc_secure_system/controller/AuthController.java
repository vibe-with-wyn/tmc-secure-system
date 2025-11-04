package com.tmc.system.tmc_secure_system.controller;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    @GetMapping("/login")
    public String login() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            // Already authenticated → redirect to permitted dashboard
            Set<String> roles = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            return "redirect:" + dashboardFor(roles);
        }
        return "login";
    }

    @GetMapping("/403")
    public String accessDenied() {
        return "403";
    }

    private String dashboardFor(Set<String> roles) {
        if (roles.contains("ROLE_ADMIN")) return "/api/admin/home";
        if (roles.contains("ROLE_IT_ANALYST")) return "/api/analyst/home";
        if (roles.contains("ROLE_OT_OPERATOR")) return "/api/ot/home";
        if (roles.contains("ROLE_COMPLIANCE_OFFICER")) return "/api/compliance/home";
        if (roles.contains("ROLE_CISO")) return "/api/ciso/home";
        return "/health"; // fallback
    }
}
