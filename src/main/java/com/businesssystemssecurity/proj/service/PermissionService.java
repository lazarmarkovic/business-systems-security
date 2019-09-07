package com.businesssystemssecurity.proj.service;

import com.businesssystemssecurity.proj.domain.Permission;

import java.util.ArrayList;

public interface PermissionService {

    Permission findById(long id);

    ArrayList<Permission> findAll();
}
