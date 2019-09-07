package com.businesssystemssecurity.proj.seeder.data;

import com.businesssystemssecurity.proj.domain.Permission;
import com.businesssystemssecurity.proj.repository.PermissionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;
import java.util.*;

@Component
public class PermissionTableSeed {

    @Autowired
    private PermissionRepository permissionRepository;

    private Logger logger = LoggerFactory.getLogger(PermissionTableSeed.class);

    public static final String REGISTER_USERS = "register_users";
    public static final String EDIT_USER_PERMISSIONS = "edit_user_permissions";
    public static final String SUSPEND_USER = "suspend_user";
    public static final String ISSUE_ROOT_CERTIFICATE = "issue_root_certificate";
    public static final String ISSUE_INTERMEDIATE_CERTIFICATE = "issue_intermediate_certificate";
    public static final String ISSUE_USER_CERTIFICATE = "issue_user_certificate";
    public static final String REVOKE_ROOT_CERTIFICATE = "revoke_root_certificate";
    public static final String REVOKE_INTERMEDIATE_CERTIFICATE = "revoke_intermediate_certificate";
    public static final String REVOKE_USER_CERTIFICATE = "revoke_user_certificate";
    public static final String DISTRIBUTE_ROOT_CERTIFICATE = "distribute_root_certificate";
    public static final String DISTRIBUTE_INTERMEDIATE_CERTIFICATE = "distribute_intermediate_certificate";
    public static final String DISTRIBUTE_USER_CERTIFICATE = "distribute_user_certificate";


    public final String[] DATA = {
            REGISTER_USERS,
            EDIT_USER_PERMISSIONS,
            SUSPEND_USER,
            ISSUE_ROOT_CERTIFICATE,
            ISSUE_INTERMEDIATE_CERTIFICATE,
            ISSUE_USER_CERTIFICATE,
            REVOKE_ROOT_CERTIFICATE,
            REVOKE_INTERMEDIATE_CERTIFICATE,
            REVOKE_USER_CERTIFICATE,
            DISTRIBUTE_ROOT_CERTIFICATE,
            DISTRIBUTE_INTERMEDIATE_CERTIFICATE,
            DISTRIBUTE_USER_CERTIFICATE
    };


    @Transactional
    public void seed() {
        for (String permission_name : this.DATA) {
            Optional<Permission> found_perm = permissionRepository.findByName(permission_name);
            if (found_perm.isPresent()) {
                logger.info("Permission " + permission_name + "already added.");
                return;
            }

            Permission new_permission = new Permission();
            new_permission.setName(permission_name);
            permissionRepository.save(new_permission);
            logger.info("Added permission: " + new_permission);
        }

    }

}
