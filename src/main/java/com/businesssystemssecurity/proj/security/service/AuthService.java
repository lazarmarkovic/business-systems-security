package com.businesssystemssecurity.proj.security.service;

import com.businesssystemssecurity.proj.domain.User;

public interface AuthService {

    String authenticate(String email, String password);

    User getAuthUser();

    boolean hasPermission(String permission);
}