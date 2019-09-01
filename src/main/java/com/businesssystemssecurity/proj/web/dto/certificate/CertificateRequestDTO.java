package com.businesssystemssecurity.proj.web.dto.certificate;

import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.web.dto.subject.SubjectDTO;

public class CertificateRequestDTO {

    private String issuerSerialNumber = "";

    private String commonName = "";
    private String organizationUnit = "";
    private String organization = "";
    private String locality = "";
    private String state = "";
    private String country = "";

    public CertificateRequestDTO() {
    }

    public SubjectDTO getSubjectDTO() {
        return new SubjectDTO(
                this.commonName,
                this.organizationUnit,
                this.organization,
                this.locality,
                this.state,
                this.country
        );
    }

    private CertificateType certificateType = CertificateType.ROOT;

    public String getIssuerSerialNumber() {
        return issuerSerialNumber;
    }

    public void setIssuerSerialNumber(String issuerSerialNumber) {
        this.issuerSerialNumber = issuerSerialNumber;
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

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
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
