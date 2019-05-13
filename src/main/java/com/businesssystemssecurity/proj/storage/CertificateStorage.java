package com.businesssystemssecurity.proj.storage;


import com.businesssystemssecurity.proj.domain.helper.CertificateKeyBind;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.exception.PKIMalfunctionException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

@Component
public class CertificateStorage {


    @Value( "${keystore.alias-name}" )
    private String keyStoreAliasName;

    @Value( "${keystore.password}" )
    private char[] keyStorePassword;

    public String[] store(CertificateKeyBind[] boundChain, CertificateType type) {

        CertificateKeyBind leafCertificate = boundChain[0];
        Path storagePath = Paths.get("src", "main", "resources", "storage", type.toString());

        try {
            String certFileName = "cert_" + leafCertificate.getCertificate().getSerialNumber() + ".cer";
            String trustFileName = "trust_" + leafCertificate.getCertificate().getSerialNumber() + ".jks";

            String certFilePath = Paths.get(storagePath.toString(), certFileName).toString();
            String trustFilePath = Paths.get(storagePath.toString(), trustFileName).toString();

            FileOutputStream out = new FileOutputStream(certFilePath);
            out.write(leafCertificate.getCertificate().getEncoded());
            out.close();

            storePrivateKey(leafCertificate.getPrivateKey(),
                    this.toCertChain(boundChain),
                    trustFilePath
            );

            return new String[]{certFilePath, trustFilePath};

        } catch (Exception e) {
            throw new PKIMalfunctionException("Error while storing root certificate.");
        }
    }

    private X509Certificate[] toCertChain(CertificateKeyBind[] ckb) {
        ArrayList<X509Certificate> chain = new ArrayList<>();

        return Arrays.stream(ckb)
                .map(CertificateKeyBind::getCertificate)
                .toArray(X509Certificate[]::new);
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

    private X509Certificate readCertificate(String certificateFilePath) {
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
}
