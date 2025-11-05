package com.tmc.system.tmc_secure_system.controller;

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import com.tmc.system.tmc_secure_system.entity.EncryptedFile;
import com.tmc.system.tmc_secure_system.entity.User;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentPermission;
import com.tmc.system.tmc_secure_system.entity.enums.RoleName;
import com.tmc.system.tmc_secure_system.repository.EncryptedFileRepository;
import com.tmc.system.tmc_secure_system.repository.FileAssignmentRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;
import com.tmc.system.tmc_secure_system.service.AssignmentService;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class AdminController {

    private final EncryptedFileRepository fileRepo;
    private final UserRepository userRepo;
    private final FileAssignmentRepository assignmentRepo;
    private final AssignmentService assignmentService;

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/api/admin/home")
    public String admin(Model model) {
        List<EncryptedFile> files = fileRepo.findAllOrderByUploadTimeDesc();
        List<User> analysts = userRepo.findAllByRole(RoleName.IT_ANALYST);
        model.addAttribute("files", files);
        model.addAttribute("analysts", analysts);
        model.addAttribute("activeAssignments", assignmentRepo.findActiveWithJoins(com.tmc.system.tmc_secure_system.entity.enums.AssignmentStatus.ACTIVE));
        return "dashboard/admin";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/api/admin/assign")
    public String assign(@RequestParam("fileId") Long fileId,
                         @RequestParam("analystId") Long analystId,
                         @RequestParam(value = "permissions", required = false) Set<AssignmentPermission> permissions,
                         @RequestParam(value = "expiresAt", required = false)
                         @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime expiresAt,
                         Principal principal,
                         Model model) {
        Long adminId = userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal.getName(), principal.getName())
                .map(User::getId).orElseThrow();

        try {
            assignmentService.assignFile(fileId, analystId, adminId,
                    permissions == null ? EnumSet.noneOf(AssignmentPermission.class) : permissions,
                    expiresAt);
            model.addAttribute("success", "Assignment created.");
        } catch (Exception ex) {
            model.addAttribute("error", ex.getMessage());
        }
        return "redirect:/api/admin/home";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/api/admin/assignments/{id}/revoke")
    public String revoke(@PathVariable("id") Long assignmentId, Model model) {
        try {
            assignmentService.revoke(assignmentId);
            model.addAttribute("success", "Assignment revoked.");
        } catch (Exception ex) {
            model.addAttribute("error", ex.getMessage());
        }
        return "redirect:/api/admin/home";
    }
}
