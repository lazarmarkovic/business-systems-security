package com.businesssystemssecurity.proj.domain;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "certificate")
public class Certificate {

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @ManyToOne(fetch=FetchType.LAZY, cascade={CascadeType.PERSIST, CascadeType.MERGE})
    private Certificate parent;

    @OneToMany(mappedBy="parent", fetch=FetchType.LAZY, cascade={CascadeType.PERSIST, CascadeType.MERGE})
    private List<Certificate> children;

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

    @Column(name="key_store_file_path")
    private String keyStoreFilePath;

    @Column(name="trust_store_file_path")
    private String trustStoreFilePath;

    @Column(name="active", nullable = false)
    private Boolean active;


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Certificate getParent() {
        return parent;
    }

    public void setParent(Certificate parent) {
        this.parent = parent;
    }

    public List<Certificate> getChildren() {
        return children;
    }

    public void setChildren(List<Certificate> children) {
        this.children = children;
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

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }
}
