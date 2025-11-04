package com.tmc.system.tmc_secure_system.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AnalystController {

    @PreAuthorize("hasRole('IT_ANALYST')")
    @GetMapping("/api/analyst/home")
    public String home() {
        return "IT Analyst Dashboard (placeholder)";
    }
}
