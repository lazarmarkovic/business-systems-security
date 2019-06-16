package com.businesssystemssecurity.proj.web.dto.certificate;

import com.businesssystemssecurity.proj.domain.Certificate;

public class CertificateDTO {
    private long id;
    private String serialNumber;
    private String issuer;
    private String subject;
    private Boolean CA;
    private Boolean active;

    public CertificateDTO() {}


    public CertificateDTO(Certificate c) {
        this.id = c.getId();
        this.serialNumber = c.getSerialNumber();
        this.issuer = c.getIssuer();
        this.subject = c.getSubject();
        this.CA = c.getCA();
        this.active = c.getActive();
    }

    public CertificateDTO(long id, String serialNumber, String issuer, String subject, Boolean CA, Boolean active) {
        this.id = id;
        this.serialNumber = serialNumber;
        this.issuer = issuer;
        this.subject = subject;
        this.CA = CA;
        this.active = active;
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

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }
}
