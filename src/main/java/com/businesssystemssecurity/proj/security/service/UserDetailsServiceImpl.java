package com.businesssystemssecurity.proj.security.service;

import java.util.List;
import java.util.stream.Collectors;

import com.businesssystemssecurity.proj.domain.User;
import com.businesssystemssecurity.proj.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserService userService;


    @Override
    public UserDetails loadUserByUsername(String email) {
        User user = userService.findByEmail(email);

        List<GrantedAuthority> grantedAuthorities = user.getUserAuthorities().
                stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthority().getName()))
                .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                grantedAuthorities);
    }
}