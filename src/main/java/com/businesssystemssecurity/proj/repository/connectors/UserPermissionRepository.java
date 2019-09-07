package com.businesssystemssecurity.proj.repository.connectors;

import com.businesssystemssecurity.proj.domain.UserAuthority;
import com.businesssystemssecurity.proj.domain.UserPermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Optional;

@Repository
public interface UserPermissionRepository extends JpaRepository<UserPermission, Long> {

    ArrayList<UserPermission> findUserPermissionsByUserId(long id);

    void deleteUserPermissionsByUserId(long id);
}