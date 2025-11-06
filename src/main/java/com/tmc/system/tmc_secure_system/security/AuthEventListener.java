package com.tmc.system.tmc_secure_system.security;

import java.time.LocalDateTime;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.tmc.system.tmc_secure_system.entity.IncidentLog;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentSeverity;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentStatus;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentType;
import com.tmc.system.tmc_secure_system.repository.IncidentLogRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthEventListener {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_MINUTES = 15;

    private final UserRepository userRepository;
    private final IncidentLogRepository incidentLogRepository;

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

            IncidentLog log = new IncidentLog();
            log.setEventType(IncidentType.FAILED_LOGIN);
            log.setSeverity(attempts >= MAX_FAILED_ATTEMPTS ? IncidentSeverity.HIGH : IncidentSeverity.MEDIUM);
            log.setStatus(IncidentStatus.OPEN);
            log.setActor(user);
            log.setUsername(user.getUsername());
            log.setDescription("Failed login attempt " + attempts + " for user");
            populateRequestContext(log);
            incidentLogRepository.save(log);

            if (justLocked) {
                IncidentLog lockLog = new IncidentLog();
                lockLog.setEventType(IncidentType.ACCOUNT_LOCKED);
                lockLog.setSeverity(IncidentSeverity.HIGH);
                lockLog.setStatus(IncidentStatus.OPEN);
                lockLog.setActor(user);
                lockLog.setUsername(user.getUsername());
                lockLog.setDescription("Account locked due to excessive failed logins");
                populateRequestContext(lockLog);
                incidentLogRepository.save(lockLog);
            }

        }, () -> {
            IncidentLog log = new IncidentLog();
            log.setEventType(IncidentType.FAILED_LOGIN);
            log.setSeverity(IncidentSeverity.MEDIUM);
            log.setStatus(IncidentStatus.OPEN);
            log.setUsername(principal);
            log.setDescription("Failed login with unknown username/email");
            populateRequestContext(log);
            incidentLogRepository.save(log);
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

            // Audit: login success
            IncidentLog ok = new IncidentLog();
            ok.setEventType(IncidentType.LOGIN_SUCCESS);
            ok.setSeverity(IncidentSeverity.LOW);
            ok.setStatus(IncidentStatus.OPEN);
            ok.setActor(user);
            ok.setUsername(user.getUsername());
            ok.setDescription("User logged in successfully");
            populateRequestContext(ok);
            incidentLogRepository.save(ok);
        });
    }

    @EventListener
    @Transactional
    public void onLogout(LogoutSuccessEvent e) {
        String principal = e.getAuthentication() != null ? e.getAuthentication().getName() : null;
        if (principal == null) return;

        userRepository.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal, principal).ifPresent(user -> {
            IncidentLog log = new IncidentLog();
            log.setEventType(IncidentType.LOGOUT);
            log.setSeverity(IncidentSeverity.LOW);
            log.setStatus(IncidentStatus.OPEN);
            log.setActor(user);
            log.setUsername(user.getUsername());
            log.setDescription("User logged out");
            populateRequestContext(log);
            incidentLogRepository.save(log);
        });
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

    private String clientIp(HttpServletRequest request) {

        String[] headers = {"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"};

        for (String h : headers) {

            String v = request.getHeader(h);

            if (v != null && !v.isBlank()) return v.split(",")[0].trim();

        }

        return request.getRemoteAddr();
        
    }
}