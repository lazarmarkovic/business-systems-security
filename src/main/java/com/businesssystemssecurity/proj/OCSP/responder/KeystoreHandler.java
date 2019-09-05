package com.businesssystemssecurity.proj.OCSP.responder;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import static net.maritimecloud.pki.PKIConstants.KEYSTORE_TYPE;

@Component
public class KeystoreHandler {

    @Value("${pki.ocsp-responder.keystore.resource}")
    private Resource signingCAKeyStoreResource;
    @Value("${pki.ocsp-responder.keystore.password}")
    private char[] signingCAKeyStorePassword;
    @Value("${pki.ocsp-responder.keystore.type}")
    private String signingCAKeyStoreType;

    @Value("${pki.ocsp-responder.key.password}")
    private char[] signingCAKeyPassword;

    @Value("${pki.ocsp-responder.truststore.resource}")
    private Resource signingCATrustStoreResource;
    @Value("${pki.ocsp-responder.truststore.password}")
    private char[] signingCATrustStorePassword;
    @Value("${pki.ocsp-responder.truststore.type}")
    private String signingCATrustStoreType;


    /**
     * Loads the MCP certificate used for signing from the (jks) keystore
     *
     * @param alias Alias of the signing certificate
     * @return a PrivateKeyEntry of the signing certificate
     */
    public KeyStore.PrivateKeyEntry getSigningCertEntry(String alias) {
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(this.signingCAKeyStoreType);
            keystore.load(this.signingCAKeyStoreResource.getInputStream(), this.signingCAKeyStorePassword);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(this.signingCAKeyPassword);
            return (KeyStore.PrivateKeyEntry) keystore.getEntry(alias, protParam);

        } catch (NoSuchAlgorithmException |
                CertificateException |
                IOException |
                KeyStoreException |
                UnrecoverableEntryException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns a MCP certificate from the truststore
     *
     * @param alias Either ROOT_CERT_ALIAS or INTERMEDIATE_CERT_ALIAS
     * @return a certificate
     */
    Certificate getMCCertificate(String alias) {
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(this.signingCAKeyStoreType);
            keystore.load(this.signingCAKeyStoreResource.getInputStream(), this.signingCAKeyStorePassword);
            return keystore.getCertificate(alias);

        } catch (NoSuchAlgorithmException |
                CertificateException |
                IOException |
                KeyStoreException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}