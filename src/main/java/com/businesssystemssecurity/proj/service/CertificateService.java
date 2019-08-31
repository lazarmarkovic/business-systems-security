package com.businesssystemssecurity.proj.service;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.web.dto.tree.TreeItem;

import java.util.ArrayList;

public interface CertificateService {

    Certificate findById(int id);

    Certificate findBySerialNumber(String serialNumber);

    ArrayList<Certificate> findAll();

    ArrayList<TreeItem> getTree();

    Certificate createRootCertificate(String subject);

    Certificate createSignedCertificate(String subject, String issuer, CertificateType certificateType);


}

