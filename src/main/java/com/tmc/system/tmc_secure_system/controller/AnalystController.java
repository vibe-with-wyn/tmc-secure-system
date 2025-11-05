package com.tmc.system.tmc_secure_system.controller;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import com.tmc.system.tmc_secure_system.dto.AssignmentView;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentPermission;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentStatus;
import com.tmc.system.tmc_secure_system.repository.FileAssignmentRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;
import com.tmc.system.tmc_secure_system.service.AnalystQueryService;
import com.tmc.system.tmc_secure_system.service.FileDownloadService;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class AnalystController {

    private final FileAssignmentRepository assignmentRepo;
    private final UserRepository userRepo;
    private final AnalystQueryService analystQueryService;
    private final FileDownloadService fileDownloadService;

    @PreAuthorize("hasRole('IT_ANALYST')")
    @GetMapping("/api/analyst/home")
    public String home(Model model, Principal principal) {
        List<AssignmentView> assignments =
                analystQueryService.listActiveAssignmentsForPrincipal(principal.getName());
        model.addAttribute("assignments", assignments);
        return "dashboard/it-analyst";
    }

    @PreAuthorize("hasRole('IT_ANALYST')")
    @GetMapping("/api/analyst/files/{id}/download")
    public ResponseEntity<byte[]> downloadDecrypted(@PathVariable("id") Long fileId, Principal principal) {
        var user = userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal.getName(), principal.getName())
                .orElseThrow();

        boolean allowed = assignmentRepo.hasPermission(
                fileId, user.getId(), AssignmentStatus.ACTIVE, AssignmentPermission.DECRYPT);

        if (!allowed) {
            return ResponseEntity.status(403).build();
        }

        byte[] plaintext = fileDownloadService.decryptPlaintext(fileId);

        String filename = "file-" + fileId + ".xlsx";
        String contentDisposition = "attachment; filename*=UTF-8''" +
                URLEncoder.encode(filename, StandardCharsets.UTF_8);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, contentDisposition)
                .contentType(MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .body(plaintext);
    }
}
