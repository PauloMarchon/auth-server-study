package com.paulomarchon.authserver.appuser;

import com.paulomarchon.authserver.appuser.payload.AppUserDto;
import com.paulomarchon.authserver.appuser.payload.AppUserRegistrationRequest;
import com.paulomarchon.authserver.common.MessageDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("api/v1/appuser")
public class AppUserController {
    private final AppUserService appUserService;

    public AppUserController(AppUserService appUserService) {
        this.appUserService = appUserService;
    }

    @GetMapping()
    public List<AppUserDto> getAppUsers(){
        return appUserService.getAllAppUsers();
    }

    @GetMapping("{appUserId}")
    public AppUserDto getAppUser(@PathVariable("appUserId")UUID appUserId) {
        return appUserService.getAppUser(appUserId);
    }

    @GetMapping("{appUserUsername}")
    public AppUserDto getAppUserByUsername(@PathVariable("appUserUsername") String username) {
        return appUserService.getAppUserByUsername(username);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerAppUser(@RequestBody AppUserRegistrationRequest userRegistrationRequest){

        appUserService.registerAppUser(userRegistrationRequest);

        MessageDto messageDto = new MessageDto("user registered successfully");

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(messageDto);
    }

    @DeleteMapping("{appUserId}")
    public void deleteAppUser(@PathVariable("appUserId") UUID appUserId) {
        appUserService.deleteAppUserById(appUserId);
    }

    public void uploadAppUserAvatarImage() {
        //TODO
    }
    public void uploadAppUserBannerImage() {
        //TODO
    }
}
