package com.tmc.system.tmc_secure_system.security;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import com.tmc.system.tmc_secure_system.entity.IncidentLog;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentSeverity;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentStatus;
import com.tmc.system.tmc_secure_system.entity.enums.IncidentType;
import com.tmc.system.tmc_secure_system.repository.IncidentLogRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;
import com.tmc.system.tmc_secure_system.service.LogHelper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class LoggingAccessDeniedHandler implements AccessDeniedHandler {

    private final IncidentLogRepository incidentRepo;
    private final UserRepository userRepo;
    private final LogHelper logHelper;

    public LoggingAccessDeniedHandler(IncidentLogRepository incidentRepo, UserRepository userRepo, LogHelper logHelper) {
        this.incidentRepo = incidentRepo;
        this.userRepo = userRepo;
        this.logHelper = logHelper;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String principal = auth != null ? auth.getName() : "anonymous";

        var log = new IncidentLog();
        log.setEventType(IncidentType.UNAUTHORIZED_ACCESS);
        log.setSeverity(IncidentSeverity.MEDIUM);
        log.setStatus(IncidentStatus.OPEN);
        log.setDescription("Access denied to " + request.getMethod() + " " + request.getRequestURI());

        logHelper.enrichIncident(log, principal);
        userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(principal, principal).ifPresent(log::setActor);
        incidentRepo.save(log);

        response.sendRedirect(request.getContextPath() + "/403");
    }
}