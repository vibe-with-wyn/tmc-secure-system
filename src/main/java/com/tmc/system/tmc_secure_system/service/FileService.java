package com.tmc.system.tmc_secure_system.service;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import com.tmc.system.tmc_secure_system.entity.EncryptedFile;
import com.tmc.system.tmc_secure_system.entity.User;
import com.tmc.system.tmc_secure_system.entity.enums.FileStatus;
import com.tmc.system.tmc_secure_system.repository.EncryptedFileRepository;
import com.tmc.system.tmc_secure_system.repository.UserRepository;
import com.tmc.system.tmc_secure_system.util.crypto.HashUtil;

@Service
public class FileService {

    private final EncryptionService encryptionService;
    private final EncryptedFileRepository fileRepo;
    private final UserRepository userRepo;
    private final String appAesKeyId; // injected from CryptoConfig

    public FileService(EncryptionService encryptionService,
                       EncryptedFileRepository fileRepo,
                       UserRepository userRepo,
                       String appAesKeyId) {
        this.encryptionService = encryptionService;
        this.fileRepo = fileRepo;
        this.userRepo = userRepo;
        this.appAesKeyId = appAesKeyId;
    }

    @Transactional
    public EncryptedFile encryptAndStore(MultipartFile file, String principalName) {
        User uploader = userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(principalName, principalName)
                .orElseThrow(() -> new IllegalArgumentException("Uploader not found"));

        byte[] bytes = toBytes(file);
        var enc = encryptionService.encrypt(bytes);

        EncryptedFile ef = new EncryptedFile();
        ef.setFilename(file.getOriginalFilename());
        ef.setContentType(file.getContentType());
        ef.setSizeBytes(file.getSize());
        ef.setUploader(uploader);
        ef.setUploadTime(LocalDateTime.now());
        ef.setFileHash(enc.sha256Ciphertext());
        ef.setAesKeyRef(appAesKeyId);
        ef.setIv(HashUtil.base64(enc.iv()));
        ef.setCiphertext(enc.ciphertext());
        ef.setStatus(FileStatus.ENCRYPTED);
        ef.setRemarks("Encrypted and stored");

        return fileRepo.save(ef);
    }

    private byte[] toBytes(MultipartFile file) {
        try {
            return file.getBytes();
        } catch (Exception e) {
            throw new IllegalStateException("Failed reading file", e);
        }
    }
}