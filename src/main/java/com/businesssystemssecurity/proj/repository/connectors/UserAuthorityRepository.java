package com.businesssystemssecurity.proj.repository.connectors;

import com.businesssystemssecurity.proj.domain.UserAuthority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserAuthorityRepository extends JpaRepository<UserAuthority, Long> {

}