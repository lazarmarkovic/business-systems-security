package com.businesssystemssecurity.proj.security.service;

import com.businesssystemssecurity.proj.domain.Permission;
import com.businesssystemssecurity.proj.domain.User;
import com.businesssystemssecurity.proj.domain.UserPermission;
import com.businesssystemssecurity.proj.exception.AccessDeniedException;
import com.businesssystemssecurity.proj.exception.UserUnauthorizedException;
import com.businesssystemssecurity.proj.security.conf.TokenUtils;
import com.businesssystemssecurity.proj.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private TokenUtils tokenUtils;

    @Autowired
    private UserService userService;


    @Override
    public String authenticate(String email, String password) {
        // Perform check if user exists
        User u = userService.findByEmail(email);

        // Perform the authentication
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(email, password);
        Authentication authentication = authenticationManager.authenticate(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Reload user details so we can generate token
        UserDetails details = userDetailsService.loadUserByUsername(email);
        return tokenUtils.generateToken(details);
    }

    @Override
    public User getAuthUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null)
            throw new UserUnauthorizedException();

        UserDetails userDetails = (UserDetails)auth.getPrincipal();
        User authUser = userService.findByEmail(userDetails.getUsername());

        if (authUser.isSuspended()) {
            throw new AccessDeniedException("User is suspended.");
        }

        return authUser;
    }

    @Override
    public boolean hasPermission(String permission) {
        Set<UserPermission> userPermissions = this.getAuthUser().getUserPermissions();
        for (UserPermission up : userPermissions) {
            if (up.getPermission().getName().equals(permission)) {
                return true;
            }
        }
        return false;
    }


}
