package com.tmc.system.tmc_secure_system.controller;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.tmc.system.tmc_secure_system.service.FileService;
import com.tmc.system.tmc_secure_system.util.excel.ExcelValidator;

@Controller
public class OtOperatorController {

    private final FileService fileService;

    @Autowired
    public OtOperatorController(FileService fileService) {
        this.fileService = fileService;
    }

    @PreAuthorize("hasRole('OT_OPERATOR')")
    @GetMapping("/api/ot/home")
    public String home() {
        return "dashboard/ot-operator";
    }

    @PreAuthorize("hasRole('OT_OPERATOR')")
    @PostMapping("/api/ot/upload")
    public String upload(@RequestParam("file") MultipartFile file, Model model, Principal principal) {
        if (file == null || file.isEmpty()) {
            model.addAttribute("error", "Please select an Excel file (.xlsx).");
            return "dashboard/ot-operator";
        }
        if (!file.getOriginalFilename().toLowerCase().endsWith(".xlsx")) {
            model.addAttribute("error", "Only .xlsx files are supported.");
            return "dashboard/ot-operator";
        }
        try {
            var result = ExcelValidator.validate(file.getInputStream());
            if (!result.valid()) {
                model.addAttribute("error", result.message());
                return "dashboard/ot-operator";
            }

            var saved = fileService.encryptAndStore(file, principal.getName());
            model.addAttribute("success", "File validated and encrypted successfully. Ref ID: " + saved.getId());

        } catch (Exception ex) {
            model.addAttribute("error", "Upload failed: " + ex.getMessage());
        }
        return "dashboard/ot-operator";
    }
}