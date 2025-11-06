package com.tmc.system.tmc_secure_system.controller;

import java.security.Principal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tmc.system.tmc_secure_system.entity.EncryptedFile;
import com.tmc.system.tmc_secure_system.entity.FileAssignment;
import com.tmc.system.tmc_secure_system.entity.IncidentLog;
import com.tmc.system.tmc_secure_system.entity.User;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentPermission;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentStatus;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentSeverity;
import com.tmc.system.tmc_secure_system.entity.enums.RoleName;
import com.tmc.system.tmc_secure_system.entity.enums.UserStatus;
import com.tmc.system.tmc_secure_system.repository.EncryptedFileRepository;
import com.tmc.system.tmc_secure_system.repository.FileAssignmentRepository;
import com.tmc.system.tmc_secure_system.repository.IncidentLogRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;
import com.tmc.system.tmc_secure_system.entity.AuditLog;
import com.tmc.system.tmc_secure_system.repository.AuditLogRepository;

import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserRepository userRepo;
    private final EncryptedFileRepository fileRepo;
    private final FileAssignmentRepository assignmentRepo;
    private final IncidentLogRepository incidentRepo;
    private final AuditLogRepository auditLogRepo;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/api/admin/home")
    public String home(Model model,
                       @RequestParam(value = "page", defaultValue = "0") int page,
                       @RequestParam(value = "size", defaultValue = "10") int size,
                       @RequestParam(value = "user", required = false) String userFilter,
                       @RequestParam(value = "severity", required = false) IncidentSeverity severity,
                       @RequestParam(value = "from", required = false) String fromDate,
                       @RequestParam(value = "to", required = false) String toDate) {

        model.addAttribute("users", userRepo.findAll());
        model.addAttribute("analysts", userRepo.findAllByRole(RoleName.IT_ANALYST));
        model.addAttribute("files", fileRepo.findAllOrderByUploadTimeDesc());
        model.addAttribute("roles", RoleName.values());
        model.addAttribute("severities", IncidentSeverity.values());

        Pageable pageable = PageRequest.of(page, size);
        LocalDateTime from = parseDateStart(fromDate);
        LocalDateTime to = parseDateEnd(toDate);

        Long actorId = null;
        if (userFilter != null && !userFilter.isBlank()) {
            actorId = userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(userFilter.trim(), userFilter.trim())
                    .map(User::getId)
                    .orElse(null);
        }

        final Long finalActorId = actorId;
        final LocalDateTime fromTs = from;
        final LocalDateTime toTs = to;

        Specification<IncidentLog> incidentSpec = (root, query, cb) -> {
            java.util.List<Predicate> ps = new java.util.ArrayList<>();
            if (finalActorId != null) {
                Join<Object, Object> actor = root.join("actor", JoinType.LEFT);
                ps.add(cb.equal(actor.get("id"), finalActorId));
            }
            if (severity != null) {
                ps.add(cb.equal(root.get("severity"), severity));
            }
            if (fromTs != null) ps.add(cb.greaterThanOrEqualTo(root.get("eventTime"), fromTs));
            if (toTs != null) ps.add(cb.lessThanOrEqualTo(root.get("eventTime"), toTs));
            query.orderBy(cb.desc(root.get("eventTime")));
            return cb.and(ps.toArray(new Predicate[0]));
        };

        Specification<AuditLog> auditSpec = (root, query, cb) -> {
            java.util.List<Predicate> ps = new java.util.ArrayList<>();
            if (finalActorId != null) {
                Join<Object, Object> actor = root.join("actor", JoinType.LEFT);
                ps.add(cb.equal(actor.get("id"), finalActorId));
            }
            if (fromTs != null) ps.add(cb.greaterThanOrEqualTo(root.get("eventTime"), fromTs));
            if (toTs != null) ps.add(cb.lessThanOrEqualTo(root.get("eventTime"), toTs));
            query.orderBy(cb.desc(root.get("eventTime")));
            return cb.and(ps.toArray(new Predicate[0]));
        };

        Page<IncidentLog> incidents = incidentRepo.findAll(incidentSpec, pageable);
        Page<AuditLog> audits = auditLogRepo.findAll(auditSpec, pageable);

        model.addAttribute("incidents", incidents);
        model.addAttribute("audits", audits);
        model.addAttribute("userFilter", userFilter);
        model.addAttribute("severityFilter", severity);
        model.addAttribute("fromFilter", fromDate);
        model.addAttribute("toFilter", toDate);

        return "dashboard/admin";
    }

    private void logAdminAction(Principal principal, HttpServletRequest request,
                                IncidentSeverity sev, String description, Long ignoredRefId) {
        // Move to audit log (admin actions are audit)
        com.tmc.system.tmc_secure_system.entity.AuditLog log = new com.tmc.system.tmc_secure_system.entity.AuditLog();
        String username = principal != null ? principal.getName() : "system";
        log.setUsername(username);
        log.setActionType(com.tmc.system.tmc_secure_system.entity.enums.AuditAction.ADMIN_ACTION);
        log.setDescription(description);
        log.setIpAddress(request != null ? request.getRemoteAddr() : null);
        if (request != null && request.getSession(false) != null) {
            log.setSessionId(request.getSession(false).getId());
        }
        userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(username, username).ifPresent(log::setActor);
        auditLogRepo.save(log);
    }

    private static LocalDateTime parseDateStart(String s) {
        if (s == null || s.isBlank()) return null;
        LocalDate d = LocalDate.parse(s, DateTimeFormatter.ISO_DATE);
        return d.atStartOfDay();
    }

    private static LocalDateTime parseDateEnd(String s) {
        if (s == null || s.isBlank()) return null;
        LocalDate d = LocalDate.parse(s, DateTimeFormatter.ISO_DATE);
        return d.atTime(LocalTime.MAX);
    }

    @PostMapping("/api/admin/users/create")
    public String createUser(Principal principal,
                             HttpServletRequest request,
                             RedirectAttributes ra,
                             @RequestParam String username,
                             @RequestParam String email,
                             @RequestParam String password,
                             @RequestParam RoleName role) {
        if (userRepo.existsByUsernameIgnoreCase(username) || userRepo.existsByEmailIgnoreCase(email)) {
            ra.addFlashAttribute("error", "Username or email already exists.");
            return "redirect:/api/admin/home";
        }
        User u = new User();
        u.setUsername(username.trim());
        u.setEmail(email.trim());
        u.setPasswordHash(passwordEncoder.encode(password));
        u.setRole(role);
        u.setStatus(UserStatus.ACTIVE);
        userRepo.save(u);

        logAdminAction(principal, request, IncidentSeverity.MEDIUM,
                "Created user: " + username, null);

        ra.addFlashAttribute("success", "User created.");
        return "redirect:/api/admin/home";
    }

    @PostMapping("/api/admin/users/reset-password")
    public String resetPassword(Principal principal,
                                HttpServletRequest request,
                                RedirectAttributes ra,
                                @RequestParam Long userId,
                                @RequestParam String newPassword) {
        User u = userRepo.findById(userId).orElse(null);
        if (u == null) {
            ra.addFlashAttribute("error", "User not found.");
            return "redirect:/api/admin/home";
        }
        u.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepo.save(u);

        logAdminAction(principal, request, IncidentSeverity.MEDIUM,
                "Reset password for userId=" + userId, null);

        ra.addFlashAttribute("success", "Password reset.");
        return "redirect:/api/admin/home";
    }

    @PostMapping("/api/admin/users/lock")
    public String lockUser(Principal principal,
                           HttpServletRequest request,
                           RedirectAttributes ra,
                           @RequestParam Long userId) {
        return setUserStatus(principal, request, ra, userId, UserStatus.LOCKED, "Locked user ");
    }

    @PostMapping("/api/admin/users/unlock")
    public String unlockUser(Principal principal,
                             HttpServletRequest request,
                             RedirectAttributes ra,
                             @RequestParam Long userId) {
        return setUserStatus(principal, request, ra, userId, UserStatus.ACTIVE, "Unlocked user ");
    }

    @PostMapping("/api/admin/assignments/create")
    public String createAssignment(Principal principal,
                                   HttpServletRequest request,
                                   RedirectAttributes ra,
                                   @RequestParam Long fileId,
                                   @RequestParam Long analystId,
                                   @RequestParam(required = false) Set<AssignmentPermission> permissions,
                                   @RequestParam(required = false) String expiresAt
    ) {
        EncryptedFile f = fileRepo.findById(fileId).orElse(null);
        User analyst = userRepo.findById(analystId).orElse(null);
        if (f == null || analyst == null) {
            ra.addFlashAttribute("error", "Invalid file or analyst.");
            return "redirect:/api/admin/home";
        }
        User admin = userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal.getName(), principal.getName())
                .orElse(null);

        FileAssignment fa = new FileAssignment();
        fa.setFile(f);
        fa.setAnalyst(analyst);
        fa.setAssignedBy(admin);
        fa.setPermissions(permissions == null ? EnumSet.noneOf(AssignmentPermission.class) : permissions);
        fa.setStatus(AssignmentStatus.ACTIVE);
        if (expiresAt != null && !expiresAt.isBlank()) {
            fa.setExpiresAt(LocalDateTime.parse(expiresAt));
        }
        assignmentRepo.save(fa);

        logAdminAction(principal, request, IncidentSeverity.MEDIUM,
                String.format("Assigned fileId=%d to analystId=%d perms=%s", fileId, analystId,
                        fa.getPermissions().stream().map(Enum::name).collect(Collectors.joining(","))),
                null);

        ra.addFlashAttribute("success", "Assignment created.");
        return "redirect:/api/admin/home";
    }

    private String setUserStatus(Principal principal, HttpServletRequest request, RedirectAttributes ra,
                                 Long userId, UserStatus status, String action) {
        User u = userRepo.findById(userId).orElse(null);
        if (u == null) {
            ra.addFlashAttribute("error", "User not found.");
            return "redirect:/api/admin/home";
        }
        u.setStatus(status);
        userRepo.save(u);

        logAdminAction(principal, request,
                status == UserStatus.LOCKED ? IncidentSeverity.HIGH : IncidentSeverity.MEDIUM,
                action + "userId=" + userId, u.getId());

        ra.addFlashAttribute("success", "User status updated.");
        return "redirect:/api/admin/home";
    }
}
