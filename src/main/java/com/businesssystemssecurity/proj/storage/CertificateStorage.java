package com.businesssystemssecurity.proj.storage;


import com.businesssystemssecurity.proj.domain.helper.CertificatesAndKeyHolder;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.exception.PKIMalfunctionException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;


@Component
public class CertificateStorage {


    @Value( "${pki.key-alias}" )
    private String keyStoreAliasName;

    @Value( "${pki.key-store-password}" )
    private char[] keyStorePassword;

    public String[] storeCertificate(CertificatesAndKeyHolder certificatesAndKeyHolder,
                                     CertificateType type)
    {
        X509Certificate leafCertificate = certificatesAndKeyHolder.getChain()[0];
        Path storagePath = Paths.get("src", "main", "resources", "storage", type.toString());

        try {
            String certFileName = "cert_" + leafCertificate.getSerialNumber() + ".cer";
            String keyStoreFileName = "keystore_" + leafCertificate.getSerialNumber() + ".jks";
            String trustStoreFileName = "truststore_" + leafCertificate.getSerialNumber() + ".jks";

            String certFilePath = Paths.get(storagePath.toString(), certFileName).toString();
            String keyStoreFilePath = Paths.get(storagePath.toString(), keyStoreFileName).toString();
            String trustStoreFilePath = Paths.get(storagePath.toString(), trustStoreFileName).toString();

            FileOutputStream out = new FileOutputStream(certFilePath);
            out.write(leafCertificate.getEncoded());
            out.close();

            // Store private key of certificate and certificate chain to keystore
            storePrivateKeyAndChain(
                    certificatesAndKeyHolder.getPrivateKey(),
                    certificatesAndKeyHolder.getChain(),
                    keyStoreFilePath,
                    leafCertificate.getSerialNumber().toString(),
                    this.keyStorePassword
            );

            // Store certificate to new  trust store
            createTrustStorage(
                    leafCertificate,
                    trustStoreFilePath,
                    leafCertificate.getSerialNumber().toString(),
                    this.keyStorePassword

            );

            return new String[]{certFilePath, keyStoreFilePath, trustStoreFilePath};

        } catch (Exception e) {
            throw new PKIMalfunctionException("Error while storing root certificate.");
        }
    }

    public X509Certificate loadCertificate(String certificateFilePath) {
        try {
            FileInputStream fis = new FileInputStream(certificateFilePath);
            BufferedInputStream bis = new BufferedInputStream(fis);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(bis);

            return (X509Certificate) cert;
        } catch (FileNotFoundException | CertificateException e) {
            throw new PKIMalfunctionException("Error while reading certificate from given path.");
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
            KeyStore keyStore = KeyStore.getInstance("jks");
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
            KeyStore keyStore = KeyStore.getInstance("jks");
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

    public CertificatesAndKeyHolder loadPrivateKeyAndChain(
            String storePath,
            String alias,
            char[] password)
    {
        try {
            KeyStore keyStore = KeyStore.getInstance("jks");

            keyStore.load(new FileInputStream(storePath), password);
            Key key = keyStore.getKey(alias, password);

            if (key instanceof PrivateKey) {
                Certificate[] certificates = keyStore.getCertificateChain(alias);

                /* Convert to X509Certificate[]*/
                ArrayList<Certificate> clist = new ArrayList<>(Arrays.asList(certificates));
                X509Certificate[] x509Certificates = clist.toArray(new X509Certificate[clist.size()]);

                return new CertificatesAndKeyHolder(x509Certificates, (PrivateKey)key);
            } else {
                throw new PKIMalfunctionException("Error while loading certificate chain.");
            }

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        return null;
    }
}
