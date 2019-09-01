package com.businesssystemssecurity.proj.storage;


import com.businesssystemssecurity.proj.domain.helper.CertificatesAndKeyHolder;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.domain.helper.IssuerData;
import com.businesssystemssecurity.proj.exception.PKIMalfunctionException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;


@Component
public class CertificateStorage {

    @Value( "${pki.key-store-password}" )
    private char[] keyStorePassword;

    @Value("${pki.keystore-path}")
    private String keyStorePath;

    public void storeCertificateChan(X509Certificate[] chain, PrivateKey privateKey) {
        String serialNumber = chain[0].getSerialNumber().toString();
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try {
                keyStore.load(new FileInputStream(this.keyStorePath), this.keyStorePassword);
            } catch (IOException e) {
                keyStore.load(null, null);
            }

            keyStore.setKeyEntry(serialNumber, privateKey, serialNumber.toCharArray(), chain);
            keyStore.store(new FileOutputStream(this.keyStorePath), this.keyStorePassword);
        } catch (KeyStoreException |
                NoSuchAlgorithmException |
                CertificateException |
                IOException e) {
            e.printStackTrace();
            throw new PKIMalfunctionException("Error while storing certificate chain into the local keystore.");
        }
    }

    public String[] storeCertificateDistributionFiles(
            X509Certificate[] chain,
            PrivateKey privateKey,
            CertificateType type) {

        X509Certificate leafCertificate = chain[0];
        Path storagePath = Paths.get("src", "main", "resources", "d_storage", type.toString());

        try {
            String certFileName = "cert_" + leafCertificate.getSerialNumber() + ".pem";
            String keyStoreFileName = "keyStore_" + leafCertificate.getSerialNumber() + ".p12";
            String trustStoreFileName = "trustStore_" + leafCertificate.getSerialNumber() + ".p12";

            String certFilePath = Paths.get(storagePath.toString(), certFileName).toString();
            String keyStoreFilePath = Paths.get(storagePath.toString(), keyStoreFileName).toString();
            String trustStoreFilePath = Paths.get(storagePath.toString(), trustStoreFileName).toString();

            // Store certificate chain to PEM file
            JcaPEMWriter pemWrt = pemWrt = new JcaPEMWriter(new FileWriter(certFilePath));
            for (int i = 0; i < chain.length; i++) {
                pemWrt.writeObject(chain[i]);
                pemWrt.flush();

            }
            pemWrt.close();

            // Store private key of certificate and certificate chain to keystore
            this.storePrivateKeyAndChain(
                    privateKey,
                    chain,
                    keyStoreFilePath,
                    leafCertificate.getSerialNumber().toString(),
                    this.keyStorePassword
            );

            // Store certificate to new  trust store
            this.createTrustStorage(
                    leafCertificate,
                    trustStoreFilePath,
                    leafCertificate.getSerialNumber().toString(),
                    this.keyStorePassword
            );

            return new String[]{certFilePath, keyStoreFilePath, trustStoreFilePath};

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIMalfunctionException("Error while storing certificate distribution files.");
        }
    }

    private void storePrivateKeyAndChain (
            Key key,
            X509Certificate[] certificateChain,
            String storePath,
            String alias,
            char[] password)
    {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry(alias, key, password, certificateChain);
            keyStore.store(new FileOutputStream(storePath), password);

        } catch (KeyStoreException |
                IOException |
                NoSuchAlgorithmException |
                CertificateException e) {
            throw new PKIMalfunctionException("Error while storing private key.");
        }
    }

    private void createTrustStorage (
            X509Certificate certificate,
            String storePath,
            String alias,
            char[] password)
    {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setCertificateEntry(alias, certificate);
            keyStore.store(new FileOutputStream(storePath), password);

        } catch (KeyStoreException |
                IOException |
                NoSuchAlgorithmException |
                CertificateException e) {
            throw new PKIMalfunctionException("Error while storing certificate to trust store.");
        }
    }

    public CertificatesAndKeyHolder getPrivateKeyAndChain(
            String storePath,
            String certAlias,
            char[] password)
    {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");

            keyStore.load(new FileInputStream(storePath), password);
            Key key = keyStore.getKey(certAlias, password);

            if (key instanceof PrivateKey) {
                Certificate[] certificates = keyStore.getCertificateChain(certAlias);

                /* Convert to X509Certificate[]*/
                ArrayList<Certificate> certificateList = new ArrayList<>(Arrays.asList(certificates));
                X509Certificate[] x509Certificates = certificateList.toArray(new X509Certificate[certificateList.size()]);

                return new CertificatesAndKeyHolder(x509Certificates, (PrivateKey)key);
            } else {
                throw new PKIMalfunctionException("Error while loading certificate chain. Bad private key.");
            }

        } catch (KeyStoreException |
                IOException |
                NoSuchAlgorithmException |
                CertificateException |
                UnrecoverableKeyException e) {
            e.printStackTrace();
            throw new PKIMalfunctionException("Error while loading certificate chain.");
        }
    }

    public IssuerData getIssuerDataBySerialNumber(String serialNumber) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(this.keyStorePath), this.keyStorePassword);

            Key key = keyStore.getKey(serialNumber, serialNumber.toCharArray());
            if (key instanceof PrivateKey) {
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(serialNumber);
                return new IssuerData((PrivateKey) key, new JcaX509CertificateHolder(cert).getSubject(),
                        cert.getPublicKey(), cert.getSerialNumber());
            } else {
                throw new PKIMalfunctionException("Error inside getIssuerDataBySerialNumber method. Invalid private key.");
            }
        } catch (KeyStoreException |
                IOException |
                NoSuchAlgorithmException |
                CertificateException |
                UnrecoverableKeyException e) {
            e.printStackTrace();
            throw new PKIMalfunctionException("Error while assembling issuer data from certificate serial number.");
        }
    }
}
