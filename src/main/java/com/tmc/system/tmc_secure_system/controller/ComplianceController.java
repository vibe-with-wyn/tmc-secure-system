package com.tmc.system.tmc_secure_system.controller;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.LocalDateTime;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.tmc.system.tmc_secure_system.entity.AuditLog;
import com.tmc.system.tmc_secure_system.entity.IncidentLog;
import com.tmc.system.tmc_secure_system.entity.enums.AuditAction;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentSeverity;
import com.tmc.system.tmc_secure_system.repository.AuditLogRepository;
import com.tmc.system.tmc_secure_system.repository.IncidentLogRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;
import com.tmc.system.tmc_secure_system.repository.spec.LogSpecifications;
import com.tmc.system.tmc_secure_system.service.CsvExportService;
import com.tmc.system.tmc_secure_system.util.DateRanges;
import com.tmc.system.tmc_secure_system.util.UserLookups;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
@PreAuthorize("hasRole('COMPLIANCE_OFFICER')")
public class ComplianceController {

    private final IncidentLogRepository incidentRepo;
    private final AuditLogRepository auditRepo;
    private final UserRepository userRepo;
    private final CsvExportService csvExport;

    @GetMapping("/api/compliance/home")
    public String home(Model model,
                       @RequestParam(value = "page", defaultValue = "0") int page,
                       @RequestParam(value = "size", defaultValue = "10") int size,
                       @RequestParam(value = "user", required = false) String userFilter,
                       @RequestParam(value = "severity", required = false) IncidentSeverity severity,
                       @RequestParam(value = "from", required = false) String fromDate,
                       @RequestParam(value = "to", required = false) String toDate) {

        Pageable pageable = PageRequest.of(page, size);
        LocalDateTime from = DateRanges.parseStart(fromDate);
        LocalDateTime to = DateRanges.parseEnd(toDate);

        Long actorId = UserLookups.resolveActorId(userRepo, userFilter);

        Specification<IncidentLog> incidentSpec = LogSpecifications.forIncidents(actorId, severity, from, to);
        Specification<AuditLog> auditSpec = LogSpecifications.forAudits(actorId, from, to);

        Page<IncidentLog> incidents = incidentRepo.findAll(incidentSpec, pageable);
        Page<AuditLog> audits = auditRepo.findAll(auditSpec, pageable);

        model.addAttribute("incidents", incidents);
        model.addAttribute("audits", audits);
        model.addAttribute("severities", IncidentSeverity.values());

        model.addAttribute("userFilter", userFilter);
        model.addAttribute("severityFilter", severity);
        model.addAttribute("fromFilter", fromDate);
        model.addAttribute("toFilter", toDate);

        return "dashboard/compliance";
    }

    @GetMapping("/api/compliance/export/incidents.csv")
    public ResponseEntity<byte[]> exportIncidentsCsv(Principal principal,
                                                     @RequestParam(value = "user", required = false) String userFilter,
                                                     @RequestParam(value = "severity", required = false) IncidentSeverity severity,
                                                     @RequestParam(value = "from", required = false) String fromDate,
                                                     @RequestParam(value = "to", required = false) String toDate) {

        LocalDateTime from = DateRanges.parseStart(fromDate);
        LocalDateTime to = DateRanges.parseEnd(toDate);
        Long actorId = UserLookups.resolveActorId(userRepo, userFilter);

        var data = incidentRepo.findAll(LogSpecifications.forIncidents(actorId, severity, from, to));
        byte[] csv = csvExport.incidentsCsv(data);

        var log = new com.tmc.system.tmc_secure_system.entity.AuditLog();
        log.setActionType(AuditAction.LOGS_EXPORTED);
        log.setUsername(principal != null ? principal.getName() : "system");
        log.setDescription("Exported incident logs as CSV");
        userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(log.getUsername(), log.getUsername()).ifPresent(log::setActor);
        auditRepo.save(log);

        String cd = "attachment; filename*=UTF-8''" + URLEncoder.encode("incidents.csv", StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, cd)
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csv);
    }

    @GetMapping("/api/compliance/export/audits.csv")
    public ResponseEntity<byte[]> exportAuditsCsv(Principal principal,
                                                  @RequestParam(value = "user", required = false) String userFilter,
                                                  @RequestParam(value = "from", required = false) String fromDate,
                                                  @RequestParam(value = "to", required = false) String toDate) {
        LocalDateTime from = DateRanges.parseStart(fromDate);
        LocalDateTime to = DateRanges.parseEnd(toDate);
        Long actorId = UserLookups.resolveActorId(userRepo, userFilter);

        var data = auditRepo.findAll(LogSpecifications.forAudits(actorId, from, to));
        byte[] csv = csvExport.auditsCsv(data);

        var log = new com.tmc.system.tmc_secure_system.entity.AuditLog();
        log.setActionType(AuditAction.LOGS_EXPORTED);
        log.setUsername(principal != null ? principal.getName() : "system");
        log.setDescription("Exported audit logs as CSV");
        userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(log.getUsername(), log.getUsername()).ifPresent(log::setActor);
        auditRepo.save(log);

        String cd = "attachment; filename*=UTF-8''" + URLEncoder.encode("audits.csv", StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, cd)
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csv);
    }
}