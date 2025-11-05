package com.tmc.system.tmc_secure_system.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tmc.system.tmc_secure_system.entity.EncryptedFile;

public interface EncryptedFileRepository extends JpaRepository<EncryptedFile, Long> {
    boolean existsByFileHash(String fileHash);
}