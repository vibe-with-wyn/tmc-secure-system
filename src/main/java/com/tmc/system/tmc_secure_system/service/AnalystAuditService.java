package com.tmc.system.tmc_secure_system.service;

import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.tmc.system.tmc_secure_system.entity.AuditLog;
import com.tmc.system.tmc_secure_system.entity.EncryptedFile;
import com.tmc.system.tmc_secure_system.entity.IncidentLog;
import com.tmc.system.tmc_secure_system.entity.enums.AuditAction;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentSeverity;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentStatus;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentType;
import com.tmc.system.tmc_secure_system.repository.AuditLogRepository;
import com.tmc.system.tmc_secure_system.repository.IncidentLogRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AnalystAuditService {

    private final IncidentLogRepository incidentRepo;
    private final AuditLogRepository auditRepo;
    private final UserRepository userRepo;

    // INCIDENT: permission denied
    public void logDecryptDenied(String principal, Long fileId, String reason) {
        IncidentLog log = baseIncident(principal);
        log.setEventType(IncidentType.DECRYPTION_DENIED);
        log.setSeverity(IncidentSeverity.MEDIUM);
        log.setDescription("Decrypt denied for fileId=" + fileId + " — " + reason);
        incidentRepo.save(log);
    }

    // INCIDENT: integrity mismatch
    public void logIntegrityMismatch(String principal, Long fileId) {
        IncidentLog log = baseIncident(principal);
        log.setEventType(IncidentType.INTEGRITY_MISMATCH);
        log.setSeverity(IncidentSeverity.HIGH);
        log.setDescription("Integrity mismatch on fileId=" + fileId);
        incidentRepo.save(log);
    }

    // AUDIT: successful decrypt/download
    public void logDecryptSuccess(String principal, EncryptedFile ef) {
        AuditLog log = baseAudit(principal, AuditAction.DECRYPTION_SUCCESS);
        log.setDescription("Decrypted & downloaded fileId=" + ef.getId() + " (" + ef.getFilename() + ")");
        auditRepo.save(log);
    }

    private IncidentLog baseIncident(String principal) {
        IncidentLog log = new IncidentLog();
        log.setStatus(IncidentStatus.OPEN);
        log.setUsername(principal);
        userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal, principal).ifPresent(log::setActor);
        populateRequestContext(log);
        return log;
    }

    private AuditLog baseAudit(String principal, AuditAction action) {
        AuditLog log = new AuditLog();
        log.setActionType(action);
        log.setUsername(principal);
        userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal, principal).ifPresent(log::setActor);
        populateRequestContext(log);
        return log;
    }

    private void populateRequestContext(IncidentLog log) {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            HttpServletRequest req = attrs.getRequest();
            log.setIpAddress(clientIp(req));
            HttpSession session = req.getSession(false);
            log.setSessionId(session != null ? session.getId() : null);
        }
    }
    private void populateRequestContext(AuditLog log) {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            HttpServletRequest req = attrs.getRequest();
            log.setIpAddress(clientIp(req));
            HttpSession session = req.getSession(false);
            log.setSessionId(session != null ? session.getId() : null);
        }
    }
    private String clientIp(HttpServletRequest request) {
        String[] headers = {"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"};
        for (String h : headers) {
            String v = request.getHeader(h);
            if (v != null && !v.isBlank()) return v.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}