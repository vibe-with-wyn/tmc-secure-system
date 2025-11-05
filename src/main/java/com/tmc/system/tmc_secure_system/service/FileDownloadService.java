package com.tmc.system.tmc_secure_system.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tmc.system.tmc_secure_system.repository.EncryptedFileRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class FileDownloadService {

    private final EncryptedFileRepository fileRepo;
    private final DecryptionService decryptionService;

    @Transactional(readOnly = true)
    public byte[] decryptPlaintext(Long fileId) {
        var ef = fileRepo.findById(fileId).orElseThrow();
        return decryptionService.decryptWithIntegrity(ef);
    }
}