package com.tmc.system.tmc_secure_system.controller;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import com.tmc.system.tmc_secure_system.security.DashboardResolver;

@Controller
public class AuthController {

    private final DashboardResolver dashboardResolver = new DashboardResolver();

    @GetMapping("/login")
    public String login() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            Set<String> roles = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            return "redirect:" + dashboardResolver.resolve(roles);
        }
        return "login";
    }

    @GetMapping("/403")
    public String accessDenied() {
        return "403";
    }
}
