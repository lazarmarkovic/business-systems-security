package com.businesssystemssecurity.proj.domain.helper;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CertificateKeyBind {
    private X509Certificate certificate;
    private PrivateKey privateKey;

    public CertificateKeyBind() {
    }

    public CertificateKeyBind(X509Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
