package com.tmc.system.tmc_secure_system.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tmc.system.tmc_secure_system.entity.User;
import com.tmc.system.tmc_secure_system.entity.enums.RoleName;
import com.tmc.system.tmc_secure_system.entity.enums.UserStatus;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsernameIgnoreCaseOrEmailIgnoreCase(String username, String email);
    boolean existsByUsernameIgnoreCase(String username);
    boolean existsByEmailIgnoreCase(String email);

    List<User> findAllByRole(RoleName role);

    long countByStatus(UserStatus status);
}
