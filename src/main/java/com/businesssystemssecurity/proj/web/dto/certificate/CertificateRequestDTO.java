package com.businesssystemssecurity.proj.web.dto.certificate;

import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.web.dto.subject.SubjectDTO;

public class CertificateRequestDTO {

    private String issuerName = "";

    private String commonName = "";
    private String organizationUnit = "";
    private String organization = "";
    private String country = "";

    private CertificateType certificateType;


    public CertificateRequestDTO() {
    }

    public SubjectDTO getSubjectDTO() {
        return new SubjectDTO(
                this.commonName,
                this.organizationUnit,
                this.organization,
                this.country
        );
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getOrganizationUnit() {
        return organizationUnit;
    }

    public void setOrganizationUnit(String organizationUnit) {
        this.organizationUnit = organizationUnit;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public CertificateType getCertificateType() {
        return certificateType;
    }

    public void setCertificateType(CertificateType certificateType) {
        this.certificateType = certificateType;
    }
}
