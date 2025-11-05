package com.tmc.system.tmc_secure_system.service;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.springframework.stereotype.Service;

import com.tmc.system.tmc_secure_system.util.crypto.HashUtil;

@Service
public class EncryptionService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_LENGTH = 12; // 96-bit recommended for GCM

    private final SecretKey key;

    public EncryptionService(SecretKey appAesKey) {
        this.key = appAesKey;
    }

    public EncResult encrypt(byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            SecureRandom.getInstanceStrong().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);

            String sha256Ciphertext = HashUtil.sha256Base64(ciphertext);

            return new EncResult(iv, ciphertext, sha256Ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    public record EncResult(byte[] iv, byte[] ciphertext, String sha256Ciphertext) {}
}