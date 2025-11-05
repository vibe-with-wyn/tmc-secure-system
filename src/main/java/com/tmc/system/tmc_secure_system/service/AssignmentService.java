package com.tmc.system.tmc_secure_system.service;

import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.Set;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tmc.system.tmc_secure_system.entity.EncryptedFile;
import com.tmc.system.tmc_secure_system.entity.FileAssignment;
import com.tmc.system.tmc_secure_system.entity.User;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentPermission;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentStatus;
import com.tmc.system.tmc_secure_system.repository.EncryptedFileRepository;
import com.tmc.system.tmc_secure_system.repository.FileAssignmentRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AssignmentService {

    private final FileAssignmentRepository assignmentRepo;
    private final EncryptedFileRepository fileRepo;
    private final UserRepository userRepo;

    @Transactional
    public FileAssignment assignFile(Long fileId, Long analystId, Long assignedById,
                                     Set<AssignmentPermission> permissions, LocalDateTime expiresAt) {
        if (assignmentRepo.existsByFile_IdAndAnalyst_IdAndStatus(fileId, analystId, AssignmentStatus.ACTIVE)) {
            throw new IllegalStateException("Active assignment already exists for this file and analyst");
        }
        EncryptedFile file = fileRepo.findById(fileId).orElseThrow();
        User analyst = userRepo.findById(analystId).orElseThrow();
        User assignedBy = userRepo.findById(assignedById).orElseThrow();

        FileAssignment fa = new FileAssignment();
        fa.setFile(file);
        fa.setAnalyst(analyst);
        fa.setAssignedBy(assignedBy);
        fa.setAssignedAt(LocalDateTime.now());
        fa.setExpiresAt(expiresAt);
        fa.setStatus(AssignmentStatus.ACTIVE);
        fa.setPermissions(permissions == null || permissions.isEmpty()
                ? EnumSet.of(AssignmentPermission.VIEW_METADATA)
                : EnumSet.copyOf(permissions));
        return assignmentRepo.save(fa);
    }

    @Transactional
    public void revoke(Long assignmentId) {
        FileAssignment fa = assignmentRepo.findById(assignmentId).orElseThrow();
        fa.setStatus(AssignmentStatus.REVOKED);
        assignmentRepo.save(fa);
    }
}