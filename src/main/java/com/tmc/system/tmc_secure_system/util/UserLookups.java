package com.tmc.system.tmc_secure_system.util;

import com.tmc.system.tmc_secure_system.repository.UserRepository;

/**
 * Helpers for resolving actors from UI filters.
 */
public final class UserLookups {
    private UserLookups(){}

    public static Long resolveActorId(UserRepository userRepo, String userFilter) {
        if (userFilter == null || userFilter.isBlank()) return null;
        return userRepo.findByUsernameIgnoreCaseOrEmailIgnoreCase(userFilter.trim(), userFilter.trim())
                .map(u -> u.getId()).orElse(null);
    }
}