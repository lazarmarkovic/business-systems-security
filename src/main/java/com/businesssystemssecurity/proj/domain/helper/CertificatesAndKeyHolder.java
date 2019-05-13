package com.businesssystemssecurity.proj.domain.helper;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CertificatesAndKeyHolder {
    private X509Certificate[] chain;
    private PrivateKey privateKey;

    public CertificatesAndKeyHolder() {
    }

    public CertificatesAndKeyHolder(X509Certificate[] chain, PrivateKey privateKey) {
        this.chain = chain;
        this.privateKey = privateKey;
    }

    public void addToBeginning(X509Certificate certificate) {
        int length = this.chain.length;
        X509Certificate[] expendedChain = new X509Certificate[length + 1];
        expendedChain[0] = certificate;
        System.arraycopy(this.chain, 0, expendedChain, 1, length);
        this.chain = expendedChain;
    }

    public X509Certificate[] getChain() {
        return chain;
    }

    public void setChain(X509Certificate[] chain) {
        this.chain = chain;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
