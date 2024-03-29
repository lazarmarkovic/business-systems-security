package com.businesssystemssecurity.proj.repository.connectors;

import com.businesssystemssecurity.proj.domain.UserAuthority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Optional;

@Repository
public interface UserAuthorityRepository extends JpaRepository<UserAuthority, Long> {

    ArrayList<UserAuthority> findUserAuthoritiesByUserId(long id);
}