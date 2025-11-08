package com.tmc.system.tmc_secure_system.security;

import java.util.List;
import java.util.Set;

/**
 * Single source of truth for role → dashboard redirects.
 * Keeps AuthController and RoleBasedAuthSuccessHandler in sync (DRY).
 */
public class DashboardResolver {

    private static final List<RoleRoute> ORDERED = List.of(
        new RoleRoute("ROLE_ADMIN", "/api/admin/home"),
        new RoleRoute("ROLE_IT_ANALYST", "/api/analyst/home"),
        new RoleRoute("ROLE_OT_OPERATOR", "/api/ot/home"),
        new RoleRoute("ROLE_COMPLIANCE_OFFICER", "/api/compliance/home"),
        new RoleRoute("ROLE_CISO", "/api/ciso/home")
    );

    public String resolve(Set<String> roles) {
        for (RoleRoute rr : ORDERED) {
            if (roles.contains(rr.role())) return rr.route();
        }
        return "/health"; // fallback
    }

    private record RoleRoute(String role, String route) {}
}