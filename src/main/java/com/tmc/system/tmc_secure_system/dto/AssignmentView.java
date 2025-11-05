package com.tmc.system.tmc_secure_system.dto;

import java.time.LocalDateTime;

public record AssignmentView(Long id, Long fileId, String filename, LocalDateTime assignedAt) {}