package com.paulomarchon.authserver.appuser;

import com.paulomarchon.authserver.appuser.payload.AppUserDto;
import com.paulomarchon.authserver.appuser.payload.AppUserRegistrationRequest;
import com.paulomarchon.authserver.appuser.payload.AppUserUpdateRequest;
import com.paulomarchon.authserver.appuser.role.Role;
import com.paulomarchon.authserver.appuser.role.RoleName;
import com.paulomarchon.authserver.appuser.role.RoleRepository;
import com.paulomarchon.authserver.exception.DuplicateResourceException;
import com.paulomarchon.authserver.exception.ResourceNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class AppUserService {
    private final AppUserDao appUserDao;
    private final AppUserDtoMapper appUserDtoMapper;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    public AppUserService(AppUserDao appUserDao, AppUserDtoMapper appUserDtoMapper, PasswordEncoder passwordEncoder, RoleRepository roleRepository) {
        this.appUserDao = appUserDao;
        this.appUserDtoMapper = appUserDtoMapper;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
    }

    public List<AppUserDto> getAllAppUsers(){
        return appUserDao.selectAllAppUsers()
                .stream()
                .map(appUserDtoMapper)
                .collect(Collectors.toList());
    }

    public AppUserDto getAppUser(UUID appUserId) {
        return appUserDao.selectAppUserById(appUserId)
                .map(appUserDtoMapper)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "appuser with id [%s] not found".formatted(appUserId)
                ));
    }

    public AppUserDto getAppUserByEmail(String email) {
        return appUserDao.selectAppUserByEmail(email)
                .map(appUserDtoMapper)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "appuser with email [%s] not found".formatted(email)
                ));
    }

    public AppUserDto getAppUserByUsername(String username) {
        return appUserDao.selectAppUserByUsername(username)
                .map(appUserDtoMapper)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "appuser with username [%s] not found".formatted(username)
                ));
    }

    public void registerAppUser(AppUserRegistrationRequest userRegistrationRequest) {

        String email = userRegistrationRequest.email();
        if (appUserDao.existsAppUserWithEmail(email))
            throw new DuplicateResourceException("email already taken");

        String username = userRegistrationRequest.username();
        if (appUserDao.existsAppUserWithUsername(username))
            throw new DuplicateResourceException("username  is already in use");

        AppUser appUser = AppUser.builder()
                .email(userRegistrationRequest.email())
                .password(passwordEncoder.encode(userRegistrationRequest.password()))
                .username(userRegistrationRequest.username())
                .authorities(assignDefaultRole())
                .build();

        appUserDao.registerAppUser(appUser);
    }

    private Set<Role> assignDefaultRole(){
        Role userRole = roleRepository.findRoleByAuthority(RoleName.USER)
                .orElseThrow(() -> new RuntimeException("Error: role is not found!"));
        Set<Role> roles = new HashSet<>();
        roles.add(userRole);
        return roles;
    }

    public void updateAppUser(UUID appUserId, AppUserUpdateRequest updateRequest) {
        //TODO
    }

    public void deleteAppUserById(UUID appUserId) {

        if (!appUserDao.existsAppUserById(appUserId))
            throw new ResourceNotFoundException("appuser with id [%s] not found".formatted(appUserId));

        appUserDao.deleteAppUserById(appUserId);
    }

    public void uploadAppUserAvatarImage(UUID appUserId, MultipartFile file) {
        //TODO
    }

    public void uploadAppUserBannerImage(UUID appUserId, MultipartFile file) {
        //TODO
    }

}
