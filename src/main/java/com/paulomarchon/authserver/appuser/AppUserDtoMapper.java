package com.paulomarchon.authserver.appuser;

import com.paulomarchon.authserver.appuser.payload.AppUserDto;
import org.springframework.stereotype.Component;

import java.util.function.Function;

@Component
public class AppUserDtoMapper implements Function<AppUser, AppUserDto> {
    @Override
    public AppUserDto apply(AppUser appUser) {
        return null;
    }
}
