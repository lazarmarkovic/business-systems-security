package com.businesssystemssecurity.proj.service;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.web.dto.subject.SubjectDTO;
import com.businesssystemssecurity.proj.web.dto.tree.TreeItem;

import java.util.ArrayList;

public interface CertificateService {

    Certificate findById(int id);

    Certificate findBySerialNumber(String serialNumber);

    Certificate findBySubjectName(String subjectName);

    ArrayList<Certificate> findAll();

    ArrayList<TreeItem> getTree();

    Certificate createCertificate(SubjectDTO subjectDTO, String issuerSerialNumber, CertificateType type);


}

