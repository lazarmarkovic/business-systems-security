package com.businesssystemssecurity.proj.repository;

import com.businesssystemssecurity.proj.domain.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    Optional<Certificate> findBySubject(String subject);

    ArrayList<Certificate> findAllByIssuer(String issuer);

    ArrayList<Certificate> findAllByIssuerId(Long issuerId);
}
