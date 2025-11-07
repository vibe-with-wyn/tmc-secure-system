package com.tmc.system.tmc_secure_system.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tmc.system.tmc_secure_system.entity.AuditLog;
import com.tmc.system.tmc_secure_system.entity.EncryptedFile;
import com.tmc.system.tmc_secure_system.entity.enums.AuditAction;
import com.tmc.system.tmc_secure_system.repository.AuditLogRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OtAuditService {

    private final AuditLogRepository auditRepo;
    private final LogHelper logHelper;

    @Transactional
    public void logValidationFailed(String principal, String filename, String reason) {
        var log = baseFor(principal, AuditAction.VALIDATION_FAILED);
        log.setDescription("Validation failed for file '" + filename + "': " + reason);
        auditRepo.save(log);
    }

    @Transactional
    public void logUploadStored(String principal, EncryptedFile ef) {
        var log = baseFor(principal, AuditAction.FILE_UPLOAD_STORED);
        log.setDescription("Encrypted file stored. id=" + ef.getId() + ", name='" + ef.getFilename() + "'");
        auditRepo.save(log);
    }

    @Transactional
    public void logUploadFailed(String principal, String filename, String reason) {
        var log = baseFor(principal, AuditAction.FILE_UPLOAD_FAILED);
        log.setDescription("Upload failed for file '" + filename + "': " + reason);
        auditRepo.save(log);
    }

    private AuditLog baseFor(String principal, AuditAction action) {
        AuditLog log = new AuditLog();
        log.setActionType(action);
        logHelper.enrichAudit(log, principal);
        return log;
    }
}