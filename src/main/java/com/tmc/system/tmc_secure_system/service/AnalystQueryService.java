package com.tmc.system.tmc_secure_system.service;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tmc.system.tmc_secure_system.dto.AssignmentView;
import com.tmc.system.tmc_secure_system.entity.User;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentStatus;
import com.tmc.system.tmc_secure_system.repository.FileAssignmentRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AnalystQueryService {

    private final UserRepository userRepo;
    private final FileAssignmentRepository assignmentRepo;

    @Transactional(readOnly = true)
    public List<AssignmentView> listActiveAssignmentsForPrincipal(String principalName) {
        Long analystId = userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(principalName, principalName)
                .map(User::getId)
                .orElseThrow();
        return assignmentRepo.findAssignmentViews(analystId, AssignmentStatus.ACTIVE);
    }
}