package com.tmc.system.tmc_secure_system.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CisoController {

    @PreAuthorize("hasRole('CISO')")
    @GetMapping("/api/ciso/home")
    public String home() {
        return "CISO Dashboard (placeholder)";
    }
}
