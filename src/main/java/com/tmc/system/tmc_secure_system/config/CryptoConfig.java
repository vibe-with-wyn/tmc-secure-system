package com.tmc.system.tmc_secure_system.config;

import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CryptoConfig {

    @Value("${app.crypto.aes-gcm.base64-key}")
    private String base64Key;

    @Value("${app.crypto.aes-gcm.key-id:c64e5bf1-0958-4936-8586-9b5152c208b9}")
    private String keyId;

    @Bean
    public SecretKey appAesKey() {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        if (keyBytes.length != 32) {
            throw new IllegalStateException("AES-256 requires a 32-byte key. Provided: " + keyBytes.length);
        }
        return new SecretKeySpec(keyBytes, "AES");
    }

    @Bean
    public String appAesKeyId() {
        return keyId;
    }
}