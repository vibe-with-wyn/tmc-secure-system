package com.tmc.system.tmc_secure_system.controller;

import java.time.LocalDateTime;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.tmc.system.tmc_secure_system.entity.AuditLog;
import com.tmc.system.tmc_secure_system.entity.IncidentLog;
import com.tmc.system.tmc_secure_system.entity.enums.AuditAction;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentStatus;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentSeverity;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentStatus;
import com.tmc.system.tmc_secure_system.entity.enums.UserStatus;
import com.tmc.system.tmc_secure_system.repository.AuditLogRepository;
import com.tmc.system.tmc_secure_system.repository.EncryptedFileRepository;
import com.tmc.system.tmc_secure_system.repository.FileAssignmentRepository;
import com.tmc.system.tmc_secure_system.repository.IncidentLogRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.data.jpa.domain.Specification;

@Controller
@RequiredArgsConstructor
public class CisoController {

    private final IncidentLogRepository incidentRepo;
    private final AuditLogRepository auditRepo;
    private final EncryptedFileRepository fileRepo;
    private final FileAssignmentRepository assignmentRepo;
    private final UserRepository userRepo;

    @PreAuthorize("hasRole('CISO')")
    @GetMapping("/api/ciso/home")
    public String home(Model model) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime last24h = now.minusHours(24);
        LocalDateTime last7d = now.minusDays(7);

        // KPIs
        long totalFiles = fileRepo.count();
        long uploads7d = fileRepo.countByUploadTimeAfter(last7d);
        long activeAssignments = assignmentRepo.countByStatus(AssignmentStatus.ACTIVE);
        long lockedUsers = userRepo.countByStatus(UserStatus.LOCKED);

        long openIncidents = incidentRepo.count(specIncStatus(IncidentStatus.OPEN));
        long critical24h = incidentRepo.count(specIncSeveritySince(IncidentSeverity.CRITICAL, last24h));
        long failedLogins24h = auditRepo.count(specAuditActionSince(AuditAction.FAILED_LOGIN, last24h));

        // Recent activity
        var recentIncidents = incidentRepo.findAll(
                PageRequest.of(0, 10, Sort.by(Sort.Direction.DESC, "eventTime"))).map(i -> i).getContent();
        var recentAudits = auditRepo.findAll(
                PageRequest.of(0, 10, Sort.by(Sort.Direction.DESC, "eventTime"))).map(a -> a).getContent();

        model.addAttribute("totalFiles", totalFiles);
        model.addAttribute("uploads7d", uploads7d);
        model.addAttribute("activeAssignments", activeAssignments);
        model.addAttribute("lockedUsers", lockedUsers);
        model.addAttribute("openIncidents", openIncidents);
        model.addAttribute("critical24h", critical24h);
        model.addAttribute("failedLogins24h", failedLogins24h);

        model.addAttribute("recentIncidents", recentIncidents);
        model.addAttribute("recentAudits", recentAudits);

        return "dashboard/ciso";
    }

    // Specs
    private Specification<IncidentLog> specIncStatus(IncidentStatus status) {
        return (root, q, cb) -> cb.equal(root.get("status"), status);
    }
    private Specification<IncidentLog> specIncSeveritySince(IncidentSeverity sev, LocalDateTime since) {
        return (root, q, cb) -> cb.and(
                cb.equal(root.get("severity"), sev),
                cb.greaterThanOrEqualTo(root.get("eventTime"), since)
        );
    }
    private Specification<AuditLog> specAuditActionSince(AuditAction action, LocalDateTime since) {
        return (root, q, cb) -> cb.and(
                cb.equal(root.get("actionType"), action),
                cb.greaterThanOrEqualTo(root.get("eventTime"), since)
        );
    }
}
