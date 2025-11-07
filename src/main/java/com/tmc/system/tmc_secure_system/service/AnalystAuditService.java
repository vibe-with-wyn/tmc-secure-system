package com.tmc.system.tmc_secure_system.service;

import org.springframework.stereotype.Service;

import com.tmc.system.tmc_secure_system.entity.AuditLog;
import com.tmc.system.tmc_secure_system.entity.EncryptedFile;
import com.tmc.system.tmc_secure_system.entity.IncidentLog;
import com.tmc.system.tmc_secure_system.entity.enums.AuditAction;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentSeverity;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentStatus;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentType;
import com.tmc.system.tmc_secure_system.repository.AuditLogRepository;
import com.tmc.system.tmc_secure_system.repository.IncidentLogRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AnalystAuditService {

    private final IncidentLogRepository incidentRepo;
    private final AuditLogRepository auditRepo;
    private final LogHelper logHelper;

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
        logHelper.enrichIncident(log, principal);
        return log;
    }

    private AuditLog baseAudit(String principal, AuditAction action) {
        AuditLog log = new AuditLog();
        log.setActionType(action);
        logHelper.enrichAudit(log, principal);
        return log;
    }
}