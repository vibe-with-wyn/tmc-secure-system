package com.tmc.system.tmc_secure_system.service;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.tmc.system.tmc_secure_system.entity.AuditLog;
import com.tmc.system.tmc_secure_system.entity.IncidentLog;
import com.tmc.system.tmc_secure_system.util.UiDates;

import lombok.RequiredArgsConstructor;

/**
 * Central CSV export helper for logs (properly escapes fields).
 */
@Service
@RequiredArgsConstructor
public class CsvExportService {

    private final UiDates uiDates;

    public byte[] incidentsCsv(List<IncidentLog> list) {
        String header = "Time,Username,Type,Severity,Description,IP,Session\n";
        String body = list.stream().map(l -> String.join(",",
                q(uiDates.format(l.getEventTime())),
                q(l.getUsername()),
                q(String.valueOf(l.getEventType())),
                q(String.valueOf(l.getSeverity())),
                q(l.getDescription()),
                q(l.getIpAddress()),
                q(l.getSessionId())
        )).collect(Collectors.joining("\n"));
        return (header + body).getBytes(StandardCharsets.UTF_8);
    }

    public byte[] auditsCsv(List<AuditLog> list) {
        String header = "Time,Username,Action,Description,IP,Session\n";
        String body = list.stream().map(l -> String.join(",",
                q(uiDates.format(l.getEventTime())),
                q(l.getUsername()),
                q(String.valueOf(l.getActionType())),
                q(l.getDescription()),
                q(l.getIpAddress()),
                q(l.getSessionId())
        )).collect(Collectors.joining("\n"));
        return (header + body).getBytes(StandardCharsets.UTF_8);
    }

    private static String q(Object v) {
        String s = v == null ? "" : String.valueOf(v);
        s = s.replace("\"", "\"\"");
        return "\"" + s + "\"";
    }
}