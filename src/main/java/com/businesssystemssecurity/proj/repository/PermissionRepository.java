package com.businesssystemssecurity.proj.repository;

import com.businesssystemssecurity.proj.domain.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {

    Optional<Permission> findByName(String name);

    Optional<Permission> findById(Long id);

    List<Permission> findAllByOrderByIdAsc();
}
