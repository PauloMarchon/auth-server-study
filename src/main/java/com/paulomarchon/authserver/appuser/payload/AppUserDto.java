package com.paulomarchon.authserver.appuser.payload;

import com.paulomarchon.authserver.appuser.role.Role;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

public record AppUserDto(
        UUID appUserId,
        String email,
        String username,
        Set<Role> authorities,
        String avatarImageUrl,
        String bannerImageUrl,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        boolean isPremiumAccount
) {
}
