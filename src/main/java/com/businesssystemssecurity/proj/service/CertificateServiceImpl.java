package com.businesssystemssecurity.proj.service;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificateKeyBind;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.exception.PKIMalfunctionException;
import com.businesssystemssecurity.proj.storage.CertificateStorage;
import org.springframework.beans.factory.annotation.Autowired;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.X500Name;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateServiceImpl implements CertificateService {

    @Autowired
    private CertificateStorage certificateStorage;

    @Override
    public void createRootCertificate(String subject) {
        CertAndKeyGen gen = generateKeyPair();
        CertificateExtensions exts = new CertificateExtensions();

        X500Principal x500Subject = new X500Principal(subject);

        try {
            exts.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(true, -1));
            X509Certificate certificate = gen.getSelfCertificate(
                    X500Name.asX500Name(x500Subject),
                    new Date(),
                    (long) 365 * 24 * 3600,
                    exts
            );

            CertificateKeyBind ckb = new CertificateKeyBind(certificate, gen.getPrivateKey());
            String[] paths = certificateStorage.store(new CertificateKeyBind[]{ckb}, CertificateType.ROOT);

            Certificate c = new Certificate();
            c.setSerialNumber(certificate.getSerialNumber().toString());
            c.setIssuer(certificate.getIssuerDN().getName());
            c.setSubject(certificate.getSubjectDN().getName());
            c.setCA(true);
            c.setCertFilePath(paths[0]);
            c.setTrustFilePath(paths[1]);
            c.setActive(true);

        } catch (IOException |
                CertificateException |
                InvalidKeyException |
                SignatureException |
                NoSuchAlgorithmException |
                NoSuchProviderException e) {
            throw new PKIMalfunctionException("Error while creating new root certificate");
        }
    }

    private CertAndKeyGen generateKeyPair() {
        try {
            CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
            keyGen.generate(4096);
            keyGen.setRandom(SecureRandom.getInstance("SHA1PRNG", "SUN"));
            return keyGen;
        } catch (InvalidKeyException |
                NoSuchProviderException |
                NoSuchAlgorithmException e) {
            throw new PKIMalfunctionException("Error while generating key pair.");
        }
    }
}
