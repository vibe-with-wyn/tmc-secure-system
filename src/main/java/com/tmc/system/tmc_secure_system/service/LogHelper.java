package com.tmc.system.tmc_secure_system.service;

import java.util.Optional;

import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.tmc.system.tmc_secure_system.entity.AuditLog;
import com.tmc.system.tmc_secure_system.entity.IncidentLog;
import com.tmc.system.tmc_secure_system.entity.User;
import com.tmc.system.tmc_secure_system.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

/**
 * Centralized helper to populate common log fields (username, actor, IP, session).
 * Keeps controllers/services simple and consistent.
 */
@Component
@RequiredArgsConstructor
public class LogHelper {

    private final UserRepository userRepo;

    public void enrichAudit(AuditLog log, String principal) {
        log.setUsername(principal);
        findUser(principal).ifPresent(log::setActor);
        applyRequestContext(log);
    }

    public void enrichIncident(IncidentLog log, String principal) {
        log.setUsername(principal);
        findUser(principal).ifPresent(log::setActor);
        applyRequestContext(log);
    }

    public Optional<User> findUser(String principal) {
        if (principal == null || principal.isBlank()) return Optional.empty();
        return userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal, principal);
    }

    private void applyRequestContext(AuditLog log) {
        HttpServletRequest req = currentRequest();
        if (req == null) return;
        log.setIpAddress(clientIp(req));
        HttpSession session = req.getSession(false);
        log.setSessionId(session != null ? session.getId() : null);
    }

    private void applyRequestContext(IncidentLog log) {
        HttpServletRequest req = currentRequest();
        if (req == null) return;
        log.setIpAddress(clientIp(req));
        HttpSession session = req.getSession(false);
        log.setSessionId(session != null ? session.getId() : null);
    }

    private HttpServletRequest currentRequest() {
        var attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attrs != null ? attrs.getRequest() : null;
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