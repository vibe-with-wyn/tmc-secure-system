package com.tmc.system.tmc_secure_system.service;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.springframework.stereotype.Service;

import com.tmc.system.tmc_secure_system.entity.EncryptedFile;
import com.tmc.system.tmc_secure_system.util.crypto.HashUtil;

@Service
public class DecryptionService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;

    private final SecretKey key;

    public DecryptionService(SecretKey appAesKey) {
        this.key = appAesKey;
    }

    public byte[] decryptWithIntegrity(EncryptedFile ef) {
        // Integrity check on ciphertext hash
        String recomputed = HashUtil.sha256Base64(ef.getCiphertext());
        if (!recomputed.equals(ef.getFileHash())) {
            throw new IllegalStateException("Integrity check failed (ciphertext hash mismatch)");
        }

        try {
            byte[] iv = Base64.getDecoder().decode(ef.getIv());
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(ef.getCiphertext());
        } catch (Exception e) {
            throw new IllegalStateException("Decryption failed", e);
        }
    }
}