package com.tmc.system.tmc_secure_system.security;

import java.time.LocalDateTime;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.stereotype.Component;

import com.tmc.system.tmc_secure_system.entity.AuditLog;
import com.tmc.system.tmc_secure_system.entity.enums.AuditAction;
import com.tmc.system.tmc_secure_system.repository.AuditLogRepository;
import com.tmc.system.tmc_secure_system.repository.IncidentLogRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;
import com.tmc.system.tmc_secure_system.service.LogHelper;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthEventListener {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_MINUTES = 15;

    private final UserRepository userRepository;
    private final IncidentLogRepository incidentLogRepository;
    private final AuditLogRepository auditLogRepository;
    private final LogHelper logHelper;

    @EventListener
    @Transactional
    public void onAuthFailure(AuthenticationFailureBadCredentialsEvent e) {
        String principal = String.valueOf(e.getAuthentication().getPrincipal());

        userRepository.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal, principal).ifPresentOrElse(user -> {
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);
            boolean justLocked = false;
            if (attempts >= MAX_FAILED_ATTEMPTS) {
                if (user.getLockedUntil() == null || user.getLockedUntil().isBefore(LocalDateTime.now())) {
                    justLocked = true;
                }
                user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_MINUTES));
            }
            userRepository.save(user);

            // AUDIT: failed login attempt (each try)
            AuditLog a = new AuditLog();
            a.setActionType(AuditAction.FAILED_LOGIN);
            a.setDescription("Failed login attempt " + attempts + " for user");
            logHelper.enrichAudit(a, user.getUsername());
            auditLogRepository.save(a);

            if (justLocked) {
                // INCIDENT: account locked
                var lockLog = new com.tmc.system.tmc_secure_system.entity.IncidentLog();
                lockLog.setEventType(com.tmc.system.tmc_secure_system.entity.enums.IncidentType.ACCOUNT_LOCKED);
                lockLog.setSeverity(com.tmc.system.tmc_secure_system.entity.enums.IncidentSeverity.HIGH);
                lockLog.setStatus(com.tmc.system.tmc_secure_system.entity.enums.IncidentStatus.OPEN);
                lockLog.setDescription("Account locked due to excessive failed logins");
                logHelper.enrichIncident(lockLog, user.getUsername());
                incidentLogRepository.save(lockLog);
            }

        }, () -> {
            // AUDIT: failed login with unknown user
            AuditLog a = new AuditLog();
            a.setActionType(AuditAction.FAILED_LOGIN);
            a.setDescription("Failed login with unknown username/email");
            logHelper.enrichAudit(a, principal);
            auditLogRepository.save(a);
        });
    }

    @EventListener
    @Transactional
    public void onAuthSuccess(AuthenticationSuccessEvent e) {
        String principal = e.getAuthentication().getName();
        userRepository.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal, principal).ifPresent(user -> {
            boolean changed = false;
            if (user.getFailedAttempts() != 0) { user.setFailedAttempts(0); changed = true; }
            if (user.getLockedUntil() != null && user.getLockedUntil().isBefore(LocalDateTime.now())) {
                user.setLockedUntil(null); changed = true;
            }
            if (changed) userRepository.save(user);

            // AUDIT: login success
            AuditLog ok = new AuditLog();
            ok.setActionType(AuditAction.LOGIN_SUCCESS);
            ok.setDescription("User logged in successfully");
            logHelper.enrichAudit(ok, user.getUsername());
            auditLogRepository.save(ok);
        });
    }

    @EventListener
    @Transactional
    public void onLogout(LogoutSuccessEvent e) {
        String principal = e.getAuthentication() != null ? e.getAuthentication().getName() : null;
        if (principal == null) return;

        userRepository.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal, principal).ifPresent(user -> {
            // AUDIT: logout
            AuditLog log = new AuditLog();
            log.setActionType(AuditAction.LOGOUT);
            log.setDescription("User logged out");
            logHelper.enrichAudit(log, user.getUsername());
            auditLogRepository.save(log);
        });
    }
}