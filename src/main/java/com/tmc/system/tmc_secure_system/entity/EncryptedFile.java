package com.tmc.system.tmc_secure_system.entity;

import java.time.LocalDateTime;
import java.util.List;

import com.tmc.system.tmc_secure_system.entity.enums.EncryptionAlgorithm;
import com.tmc.system.tmc_secure_system.entity.enums.FileStatus;

import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Data;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Data
@Entity
@Table(name="encrypted_files", indexes = {
    @Index(name = "idx_encrypted_files_status", columnList = "status"),
    @Index(name = "idx_encrypted_files_uploader", columnList = "uploader_id")
})
public class EncryptedFile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String filename;

    @Column(name = "content_type", length = 100)
    private String contentType;

    @Column(name = "size_bytes")
    private Long sizeBytes;

    @ManyToOne
    @JoinColumn(name = "uploader_id", nullable = false)
    private User uploader;

    @Column(name = "upload_time", nullable = false)
    private LocalDateTime uploadTime = LocalDateTime.now();

    // SHA-256 of ciphertext (Base64)
    @Column(name = "file_hash", nullable = false, length = 88)
    private String fileHash;

    // Key reference/version
    @Column(name = "aes_key_ref", nullable = false, length = 64)
    private String aesKeyRef;

    // IV stored Base64 for readability
    @Column(nullable = false, length = 24)
    private String iv;

    // Store ciphertext as BYTEA and load lazily to avoid LO streaming
    @Basic(fetch = FetchType.LAZY)
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "ciphertext", nullable = false, columnDefinition = "bytea")
    private byte[] ciphertext;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private EncryptionAlgorithm algorithm = EncryptionAlgorithm.AES_GCM_256;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private FileStatus status = FileStatus.ENCRYPTED;

    @Column(columnDefinition = "TEXT")
    private String remarks;

    @OneToMany(mappedBy = "file")
    private List<FileAssignment> assignments;
}
