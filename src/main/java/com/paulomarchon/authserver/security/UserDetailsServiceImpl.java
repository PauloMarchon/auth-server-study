package com.paulomarchon.authserver.security;

import com.paulomarchon.authserver.appuser.AppUserDao;
import com.paulomarchon.authserver.exception.ResourceNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private final AppUserDao appUserDao;

    public UserDetailsServiceImpl(AppUserDao appUserDao) {
        this.appUserDao = appUserDao;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return appUserDao.selectAppUserByEmail(username)
                .orElseThrow(() -> new ResourceNotFoundException("appuser not found"));
    }
}
