package com.businesssystemssecurity.proj.service;

import com.businesssystemssecurity.proj.domain.Permission;
import com.businesssystemssecurity.proj.exception.EntityNotFoundException;
import com.businesssystemssecurity.proj.repository.PermissionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Optional;

@Service
public class PermissionServiceImpl implements PermissionService {
    @Autowired
    private PermissionRepository permissionRepository;

    @Override
    public Permission findById(long id) {
        Optional<Permission> permissions = this.permissionRepository.findById(id);

        return permissions.orElseThrow(() -> new EntityNotFoundException(Permission.class, "id", Long.toString(id)));
    }

    @Override
    public ArrayList<Permission> findAll() {
        ArrayList<Permission> listOfPermissions = (ArrayList<Permission>)this.permissionRepository.findAllByOrderByIdAsc();

        if (listOfPermissions == null) {
            throw new EntityNotFoundException(Permission.class, "all", "null");
        }

        return listOfPermissions;
    }
}
