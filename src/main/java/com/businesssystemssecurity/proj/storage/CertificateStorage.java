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


@Component
public class CertificateStorage {


    @Value( "${keystore.alias-name}" )
    private String keyStoreAliasName;

    @Value( "${keystore.password}" )
    private char[] keyStorePassword;

    public String[] storeCertificate(CertificatesAndKeyHolder certificatesAndKeyHolder,
                                     CertificateType type)
    {
        X509Certificate leafCertificate = certificatesAndKeyHolder.getChain()[0];
        Path storagePath = Paths.get("src", "main", "resources", "storage", type.toString());

        try {
            String certFileName = "cert_" + leafCertificate.getSerialNumber() + ".cer";
            String trustFileName = "trust_" + leafCertificate.getSerialNumber() + ".jks";

            String certFilePath = Paths.get(storagePath.toString(), certFileName).toString();
            String trustFilePath = Paths.get(storagePath.toString(), trustFileName).toString();

            FileOutputStream out = new FileOutputStream(certFilePath);
            out.write(leafCertificate.getEncoded());
            out.close();

            storePrivateKey(certificatesAndKeyHolder.getPrivateKey(),
                    certificatesAndKeyHolder.getChain(),
                    trustFilePath
            );

            return new String[]{certFilePath, trustFilePath};

        } catch (Exception e) {
            throw new PKIMalfunctionException("Error while storing root certificate.");
        }
    }

    public CertificatesAndKeyHolder loadChainAndKey(String trustFilePath)
    {
        try {
            KeyStore keyStore = KeyStore.getInstance("jks");

            keyStore.load(new FileInputStream(trustFilePath), this.keyStorePassword);
            Key key = keyStore.getKey(this.keyStoreAliasName, this.keyStorePassword);

            if (key instanceof PrivateKey) {
                Certificate[] certificates = keyStore.getCertificateChain(this.keyStoreAliasName);
                return new CertificatesAndKeyHolder((X509Certificate[])certificates, (PrivateKey)key);
            } else {
                throw new PKIMalfunctionException("Error while loading certificate chain.");
            }

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        return null;
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

    private void storePrivateKey(
                                 Key key,
                                 X509Certificate[] certificateChain,
                                 String keystorePath)
    {
        try {
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(null, null);
            keyStore.setKeyEntry(this.keyStoreAliasName, key, this.keyStorePassword, certificateChain);
            keyStore.store(new FileOutputStream(keystorePath), this.keyStorePassword);

        } catch (KeyStoreException |
                IOException |
                NoSuchAlgorithmException |
                CertificateException e) {
            throw new PKIMalfunctionException("Error while storing private key.");
        }

    }
}
