package com.businesssystemssecurity.proj.web.dto.certificate;

import com.businesssystemssecurity.proj.domain.Certificate;
import org.springframework.stereotype.Component;


@Component
public class CertificateDTO {

    private long id;
    private String serialNumber;
    private String caSerialNumber;
    private String issuer;
    private String subject;
    private Boolean CA;
    private Boolean revoked;
    private String revokedAt;
    private String revokeReason;
    private String type;

    private String issuedAt;
    private String expiringAt;

    public CertificateDTO() {}



    public CertificateDTO(Certificate c) {
        this.id = c.getId();
        this.serialNumber = c.getSerialNumber();
        this.caSerialNumber = c.getCaSerialNumber();
        this.issuer = c.getIssuer();
        this.subject = c.getSubject();
        this.CA = c.getCA();
        this.revoked = c.getRevoked();
        if (c.getRevokedAt() != null) {
            this.revokedAt = c.getRevokedAt().toString();
        } else {
            this.revokedAt = "--";
        }
        this.revokeReason = c.getRevokeReason();
        this.type = c.getType();
        this.issuedAt = c.getIssuedAt().toString();
        this.expiringAt = c.getExpiringAt().toString();

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

    public String getCaSerialNumber() {
        return caSerialNumber;
    }

    public void setCaSerialNumber(String caSerialNumber) {
        this.caSerialNumber = caSerialNumber;
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

    public String getRevokeReason() {
        return revokeReason;
    }

    public void setRevokeReason(String revokeReason) {
        this.revokeReason = revokeReason;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(String revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(String issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getExpiringAt() {
        return expiringAt;
    }

    public void setExpiringAt(String expiringAt) {
        this.expiringAt = expiringAt;
    }
}
