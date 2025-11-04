package com.tmc.system.tmc_secure_system.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OtOperatorController {

    @PreAuthorize("hasRole('OT_OPERATOR')")
    @GetMapping("/api/ot/home")
    public String home() {
        return "OT Operator Dashboard (placeholder)";
    }
}