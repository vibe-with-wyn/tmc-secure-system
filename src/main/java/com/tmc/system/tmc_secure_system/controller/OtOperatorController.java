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
import com.tmc.system.tmc_secure_system.service.OtAuditService;
import com.tmc.system.tmc_secure_system.util.excel.ExcelValidator;

@Controller
public class OtOperatorController {

    private final FileService fileService;
    private final OtAuditService otAuditService;

    @Autowired
    public OtOperatorController(FileService fileService, OtAuditService otAuditService) {
        this.fileService = fileService;
        this.otAuditService = otAuditService;
    }

    @PreAuthorize("hasRole('OT_OPERATOR')")
    @GetMapping("/api/ot/home")
    public String home() {
        return "dashboard/ot-operator";
    }

    @PreAuthorize("hasRole('OT_OPERATOR')")
    @PostMapping("/api/ot/upload")
    public String upload(@RequestParam("file") MultipartFile file, Model model, Principal principal) {
        String filename = file != null ? file.getOriginalFilename() : null;
        try {
            if (file == null || file.isEmpty()) {
                model.addAttribute("error", "Please select an Excel file (.xlsx).");
                otAuditService.logUploadFailed(principal.getName(), String.valueOf(filename), "No file provided");
                return "dashboard/ot-operator";
            }
            if (!file.getOriginalFilename().toLowerCase().endsWith(".xlsx")) {
                model.addAttribute("error", "Only .xlsx files are supported.");
                otAuditService.logUploadFailed(principal.getName(), filename, "Unsupported extension");
                return "dashboard/ot-operator";
            }
            var result = ExcelValidator.validate(file.getInputStream());
            if (!result.valid()) {
                model.addAttribute("error", result.message());
                otAuditService.logValidationFailed(principal.getName(), filename, result.message());
                return "dashboard/ot-operator";
            }
            var saved = fileService.encryptAndStore(file, principal.getName());
            model.addAttribute("success", "File validated and encrypted. Ref ID: " + saved.getId());
            otAuditService.logUploadStored(principal.getName(), saved);
        } catch (Exception ex) {
            model.addAttribute("error", "Upload failed: " + ex.getMessage());
            otAuditService.logUploadFailed(principal.getName(), String.valueOf(filename), ex.getMessage());
        }
        return "dashboard/ot-operator";
    }
}