package com.tmc.system.tmc_secure_system.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.tmc.system.tmc_secure_system.dto.AssignmentView;
import com.tmc.system.tmc_secure_system.entity.FileAssignment;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentPermission;
import com.tmc.system.tmc_secure_system.entity.enums.AssignmentStatus;

public interface FileAssignmentRepository extends JpaRepository<FileAssignment, Long> {

    @Query("select fa from FileAssignment fa where fa.analyst.id = :analystId and fa.status = :status")
    List<FileAssignment> findByAnalystAndStatus(@Param("analystId") Long analystId,
                                                @Param("status") AssignmentStatus status);

    @Query("""
           select (count(fa) > 0) from FileAssignment fa
             join fa.permissions p
           where fa.file.id = :fileId
             and fa.analyst.id = :analystId
             and fa.status = :status
             and p = :permission
           """)
    boolean hasPermission(@Param("fileId") Long fileId,
                          @Param("analystId") Long analystId,
                          @Param("status") AssignmentStatus status,
                          @Param("permission") AssignmentPermission permission);

    // New: DTO projection to avoid lazy issues in views
    @Query("""
           select new com.tmc.system.tmc_secure_system.dto.AssignmentView(
                 fa.id, f.id, f.filename, fa.assignedAt)
           from FileAssignment fa
             join fa.file f
           where fa.analyst.id = :analystId
             and fa.status = :status
           order by fa.assignedAt desc
           """)
    List<AssignmentView> findAssignmentViews(@Param("analystId") Long analystId,
                                             @Param("status") AssignmentStatus status);
}