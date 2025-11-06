package com.tmc.system.tmc_secure_system.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.tmc.system.tmc_secure_system.entity.AuditLog;
import com.tmc.system.tmc_secure_system.entity.EncryptedFile;
import com.tmc.system.tmc_secure_system.entity.enums.AuditAction;
import com.tmc.system.tmc_secure_system.repository.AuditLogRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OtAuditService {

    private final AuditLogRepository auditRepo;
    private final UserRepository userRepo;

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
        log.setUsername(principal);
        userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal, principal).ifPresent(log::setActor);
        populateRequestContext(log);
        return log;
    }

    private void populateRequestContext(AuditLog log) {
        var attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) return;
        HttpServletRequest req = attrs.getRequest();
        log.setIpAddress(clientIp(req));
        HttpSession session = req.getSession(false);
        log.setSessionId(session != null ? session.getId() : null);
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