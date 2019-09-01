package com.businesssystemssecurity.proj.web.dto.certificate;

import com.businesssystemssecurity.proj.domain.Certificate;

import java.util.Date;

public class CertificateDTO {
    private long id;
    private String serialNumber;
    private String issuer;
    private String subject;
    private Boolean CA;
    private Boolean revoked;
    private java.util.Date revokedAt;
    private String revokeReason;

    public CertificateDTO() {}


    public CertificateDTO(Certificate c) {
        this.id = c.getId();
        this.serialNumber = c.getSerialNumber();
        this.issuer = c.getIssuer();
        this.subject = c.getSubject();
        this.CA = c.getCA();
        this.revoked = c.getRevoked();
        this.revokedAt = c.getRevokedAt();
        this.revokeReason = c.getRevokeReason();

    }

    public CertificateDTO(long id, String serialNumber, String issuer, String subject, Boolean CA, Boolean revoked, java.util.Date revokedAt, String revokeReason) {
        this.id = id;
        this.serialNumber = serialNumber;
        this.issuer = issuer;
        this.subject = subject;
        this.CA = CA;
        this.revoked = revoked;
        this.revokedAt = revokedAt;
        this.revokeReason = revokeReason;
    }


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

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

    public Boolean getCA() {
        return CA;
    }

    public void setCA(Boolean CA) {
        this.CA = CA;
    }

    public Boolean getRevoked() {
        return revoked;
    }

    public void setRevoked(Boolean revoked) {
        this.revoked = revoked;
    }

    public Date getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(Date revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getRevokeReason() {
        return revokeReason;
    }

    public void setRevokeReason(String revokeReason) {
        this.revokeReason = revokeReason;
    }
}
