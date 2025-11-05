package com.tmc.system.tmc_secure_system.util.crypto;

import java.security.MessageDigest;
import java.util.Base64;

public final class HashUtil {
    private HashUtil(){}

    public static String sha256Base64(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            return Base64.getEncoder().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 error", e);
        }
    }

    public static String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
}