package com.paulomarchon.authserver.appuser;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AppUserDao {
    List<AppUser> selectAllAppUsers();
    Optional<AppUser> selectAppUserById(UUID id);
    void registerAppUser(AppUser appUser);
    void updateAppUser(AppUser appUser);
    void deleteAppUserById(UUID id);
    Optional<AppUser> selectAppUserByUsername(String username);
    Optional<AppUser> selectAppUserByEmail(String email);
    boolean existsAppUserById(UUID id);
    boolean existsAppUserWithUsername(String username);
    boolean existsAppUserWithEmail(String email);
    void updateAppUserAvatarImageUrl(String imageUrl, UUID appUserId);
    void updateAppUserBannerImageUrl(String imageUrl, UUID appUserId);

}
