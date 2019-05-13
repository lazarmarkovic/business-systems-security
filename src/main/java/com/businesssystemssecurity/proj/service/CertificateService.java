package com.businesssystemssecurity.proj.service;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;

import java.util.ArrayList;

public interface CertificateService {

    void createRootCertificate(String subject);

    void createSignedCertificate(String subject, String issuer, CertificateType certificateType);

    ArrayList<Certificate> findAll();
}

