package com.businesssystemssecurity.proj.repository;

import com.businesssystemssecurity.proj.domain.Authority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AuthorityRepository extends JpaRepository<Authority, Long> {

    Optional<Authority> findByName(String name);

    Optional<Authority> findById(Long id);

    List<Authority> findAllByOrderByIdAsc();
}
