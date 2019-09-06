package com.businesssystemssecurity.proj.domain;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "certificate")
public class Certificate {

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(name="serial_number", nullable = false, unique = true)
    private String serialNumber;

    @Column(name="ca_serial_number", nullable = false, unique = true)
    private String caSerialNumber;

    @Column(name="type", nullable = true)
    private String type;

    @Column(name="issuer", nullable = false)
    private String issuer;

    @Column(name="subject", nullable = false)
    private String subject;

    @Column(name="ca", nullable = false)
    private Boolean CA;

    @Column(name="cert_file_path")
    private String certFilePath;

    @Column(name="key_store_file_path")
    private String keyStoreFilePath;

    @Column(name="trust_store_file_path")
    private String trustStoreFilePath;

    @Column(name="revoked", nullable = false)
    private Boolean revoked;

    @Column(name="revoked_at", nullable = true)
    @Temporal(TemporalType.TIMESTAMP)
    private java.util.Date revokedAt;

    @Column(columnDefinition = "MEDIUMTEXT", nullable = true)
    private String revokeReason;

    @Column(name="issued_at", nullable = true)
    @Temporal(TemporalType.TIMESTAMP)
    private java.util.Date issuedAt;

    @Column(name="expiring_at", nullable = true)
    @Temporal(TemporalType.TIMESTAMP)
    private java.util.Date expiringAt;



    public Certificate() {}

    public Certificate(String serialNumber,
                       String caSerialNumber,
                       String type,
                       String issuer,
                       String subject,
                       Boolean CA,
                       String certFilePath,
                       String keyStoreFilePath,
                       String trustStoreFilePath,
                       Boolean revoked,
                       Date revokedAt,
                       String revokeReason,
                       Date issuedAt,
                       Date expiringAt)
    {
        this.serialNumber = serialNumber;
        this.caSerialNumber = caSerialNumber;
        this.type = type;
        this.issuer = issuer;
        this.subject = subject;
        this.CA = CA;
        this.certFilePath = certFilePath;
        this.keyStoreFilePath = keyStoreFilePath;
        this.trustStoreFilePath = trustStoreFilePath;
        this.revoked = revoked;
        this.revokedAt = revokedAt;
        this.revokeReason = revokeReason;
        this.issuedAt = issuedAt;
        this.expiringAt = expiringAt;
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

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
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

    public String getKeyStoreFilePath() {
        return keyStoreFilePath;
    }

    public void setKeyStoreFilePath(String keyStoreFilePath) {
        this.keyStoreFilePath = keyStoreFilePath;
    }

    public String getTrustStoreFilePath() {
        return trustStoreFilePath;
    }

    public void setTrustStoreFilePath(String trustStoreFilePath) {
        this.trustStoreFilePath = trustStoreFilePath;
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

    public Date getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Date issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Date getExpiringAt() {
        return expiringAt;
    }

    public void setExpiringAt(Date expiringAt) {
        this.expiringAt = expiringAt;
    }
}
