package com.businesssystemssecurity.proj.web.dto.certificate;

import com.businesssystemssecurity.proj.domain.helper.CertificateType;

public class CertificateRequestDTO {

    private String issuer;
    private String subject;
    private CertificateType certificateType;


    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public CertificateType getCertificateType() {
        return certificateType;
    }

    public void setCertificateType(CertificateType certificateType) {
        this.certificateType = certificateType;
    }

    @Override
    public String toString() {
        return "CertificateRequestDTO{" +
                "issuer='" + issuer + '\'' +
                ", subject='" + subject + '\'' +
                ", certificateType=" + certificateType +
                '}';
    }
}
