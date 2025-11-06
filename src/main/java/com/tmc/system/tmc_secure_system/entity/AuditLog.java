package com.tmc.system.tmc_secure_system.entity;

import java.time.LocalDateTime;

import com.tmc.system.tmc_secure_system.entity.enums.AuditAction;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_time", nullable = false)
    private LocalDateTime eventTime = LocalDateTime.now();

    @Column(length = 100)
    private String username;

    @Enumerated(EnumType.STRING)
    @Column(name = "action_type", nullable = false, length = 64)
    private AuditAction actionType;

    @Column(columnDefinition = "TEXT")
    private String description;

    @ManyToOne
    @JoinColumn(name = "actor_id")
    private User actor;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "session_id", length = 64)
    private String sessionId;
}