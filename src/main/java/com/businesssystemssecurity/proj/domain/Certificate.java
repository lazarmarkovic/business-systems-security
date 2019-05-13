package com.businesssystemssecurity.proj.domain;

import javax.persistence.*;

@Entity
@Table(name = "certificate")
public class Certificate {

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(name = "issuer_id")
    private long issuerId;

    @Column(name="serial_number", nullable = false, unique = true)
    private String serialNumber;

    @Column(name="issuer", nullable = false)
    private String issuer;

    @Column(name="subject", nullable = false)
    private String subject;

    @Column(name="ca", nullable = false)
    private Boolean CA;

    @Column(name="cert_file_path")
    private String certFilePath;

    @Column(name="trust_file_path")
    private String trustFilePath;

    @Column(name="active", nullable = false)
    private Boolean active;


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public long getIssuerId() {
        return issuerId;
    }

    public void setIssuerId(long issuerId) {
        this.issuerId = issuerId;
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

    public String getCertFilePath() {
        return certFilePath;
    }

    public void setCertFilePath(String certFilePath) {
        this.certFilePath = certFilePath;
    }

    public String getTrustFilePath() {
        return trustFilePath;
    }

    public void setTrustFilePath(String trustFilePath) {
        this.trustFilePath = trustFilePath;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }
}
