package com.tmc.system.tmc_secure_system.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.tmc.system.tmc_secure_system.entity.EncryptedFile;

@Repository
public interface EncryptedFileRepository extends JpaRepository<EncryptedFile, Long> {
    boolean existsByFileHash(String fileHash);

    @Query("select f from EncryptedFile f order by f.uploadTime desc")
    List<EncryptedFile> findAllOrderByUploadTimeDesc();
}