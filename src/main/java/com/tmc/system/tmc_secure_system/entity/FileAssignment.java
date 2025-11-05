package com.tmc.system.tmc_secure_system.entity;

import java.time.LocalDateTime;
import java.util.Set;

import com.tmc.system.tmc_secure_system.entity.enums.AssignmentPermission;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentStatus;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Index;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Data;

@Data
@Entity
@Table(
    name = "file_assignments",
    uniqueConstraints = {
        @UniqueConstraint(name = "uq_file_assignment_active", columnNames = {"file_id", "analyst_id", "status"})
    },
    indexes = {
        @Index(name = "idx_assignment_file", columnList = "file_id"),
        @Index(name = "idx_assignment_analyst", columnList = "analyst_id")
    }
)
public class FileAssignment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "file_id", nullable = false)
    private EncryptedFile file;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "analyst_id", nullable = false)
    private User analyst;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assigned_by", nullable = false)
    private User assignedBy;

    @Column(name = "assigned_at")
    private LocalDateTime assignedAt = LocalDateTime.now();

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AssignmentStatus status = AssignmentStatus.ACTIVE;

    @ElementCollection
    @CollectionTable(name = "file_assignment_permissions", joinColumns = @JoinColumn(name = "assignment_id"))
    @Column(name = "permission", length = 32, nullable = false)
    @Enumerated(EnumType.STRING)
    private Set<AssignmentPermission> permissions;
}
