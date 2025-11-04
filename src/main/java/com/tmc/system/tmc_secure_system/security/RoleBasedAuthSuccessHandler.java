package com.tmc.system.tmc_secure_system.security;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class RoleBasedAuthSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
     
        Set<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());

        String target = "/health"; // fallback
        if (roles.contains("ROLE_ADMIN")) target = "/api/admin/home";
        else if (roles.contains("ROLE_IT_ANALYST")) target = "/api/analyst/home";
        else if (roles.contains("ROLE_OT_OPERATOR")) target = "/api/ot/home";
        else if (roles.contains("ROLE_COMPLIANCE_OFFICER")) target = "/api/compliance/home";
        else if (roles.contains("ROLE_CISO")) target = "/api/ciso/home";

        response.sendRedirect(target);
    }
}