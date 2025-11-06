package com.tmc.system.tmc_secure_system.entity.enums;

public enum AuditAction {
    LOGIN_SUCCESS,
    LOGOUT,
    FAILED_LOGIN,           // individual failed attempts (for audit)
    FILE_UPLOAD_STORED,
    FILE_UPLOAD_FAILED,
    VALIDATION_FAILED,
    FILE_DOWNLOAD,
    DECRYPTION_SUCCESS,
    ADMIN_ACTION
}