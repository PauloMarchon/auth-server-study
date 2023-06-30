package com.paulomarchon.authserver.appuser;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

@Transactional
public interface AppUserRepository extends JpaRepository<AppUser, UUID> {
    Optional<AppUser> findAppUserByEmail(String email);
    Optional<AppUser> findAppUserByUsername(String username);
    boolean existsAppUserById(UUID id);
    boolean existsAppUserByEmail(String email);
    boolean existsAppUserByUsername(String username);

    @Modifying(clearAutomatically = true)
    @Query("UPDATE AppUser a SET a.avatarImageUrl = ?1 WHERE a.id = ?2")
    int updateAppUserAvatarImageUrl(String imageUrl, UUID appUserId);
    @Modifying(clearAutomatically = true)
    @Query("UPDATE AppUser a SET a.bannerImageUrl = ?1 WHERE a.id = ?2")
    int updateAppUserBannerImageUrl(String imageUrl, UUID appUserId);
}
