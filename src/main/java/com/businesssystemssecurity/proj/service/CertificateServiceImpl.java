package com.businesssystemssecurity.proj.service;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificatesAndKeyHolder;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.exception.EntityNotFoundException;
import com.businesssystemssecurity.proj.exception.PKIMalfunctionException;
import com.businesssystemssecurity.proj.repository.CertificateRepository;
import com.businesssystemssecurity.proj.storage.CertificateStorage;
import org.springframework.beans.factory.annotation.Autowired;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

import javax.security.auth.x500.X500Principal;
import javax.transaction.Transactional;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Optional;

public class CertificateServiceImpl implements CertificateService {

    @Autowired
    private CertificateStorage certificateStorage;

    @Autowired
    private CertificateRepository certificateRepository;

    @Override
    @Transactional
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

            CertificatesAndKeyHolder certificatesAndKeyHolder = new CertificatesAndKeyHolder();
            certificatesAndKeyHolder.setChain(new X509Certificate[]{certificate});
            certificatesAndKeyHolder.setPrivateKey(gen.getPrivateKey());

            String[] paths = certificateStorage.storeCertificate(certificatesAndKeyHolder, CertificateType.ROOT);

            Certificate c = new Certificate();
            c.setSerialNumber(certificate.getSerialNumber().toString());
            c.setIssuer(certificate.getIssuerDN().getName());
            c.setSubject(certificate.getSubjectDN().getName());
            c.setCA(true);
            c.setCertFilePath(paths[0]);
            c.setTrustFilePath(paths[1]);
            c.setActive(true);

            Certificate saved = certificateRepository.save(c);
            saved.setIssuerId(saved.getId());
            certificateRepository.save(saved);

        } catch (IOException |
                CertificateException |
                InvalidKeyException |
                SignatureException |
                NoSuchAlgorithmException |
                NoSuchProviderException e) {
            throw new PKIMalfunctionException("Error while creating new root certificate");
        }
    }

    @Override
    @Transactional
    public void createSignedCertificate(String subject, String issuer, CertificateType certificateType) {
        Optional<Certificate> opt = certificateRepository.findBySubject(issuer);
        Certificate issuerCertificate = opt.orElseThrow(() -> new EntityNotFoundException(Certificate.class, "issuer", issuer));

        CertificatesAndKeyHolder ckh = certificateStorage.loadChainAndKey(issuerCertificate.getTrustFilePath());

        X500Principal x500Subject = new X500Principal(subject);
        Principal issuerName = ckh.getChain()[0].getSubjectDN();
        String issuerSigAlg = ckh.getChain()[0].getSigAlgName();
        CertAndKeyGen sub = generateKeyPair();

        try {


            X509Certificate certificate = sub.getSelfCertificate(
                    X500Name.asX500Name(x500Subject),
                    (long) 365 * 24 * 3600);

            X509CertInfo info = new X509CertInfo(certificate.getTBSCertificate());
            info.set(X509CertInfo.ISSUER, issuerName);

            CertificateExtensions exts = new CertificateExtensions();
            if (certificateType == CertificateType.USER) {
                exts.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(false, -1));
            } else {
                exts.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(true, -1));
            }

            info.set(X509CertInfo.EXTENSIONS, exts);
            X509CertImpl outCertificate = new X509CertImpl(info);
            outCertificate.sign(ckh.getPrivateKey(), issuerSigAlg);

            ckh.addToBeginning(outCertificate);

            String[] paths = certificateStorage.storeCertificate(ckh, certificateType);

            Certificate newCertificate = new Certificate();
            newCertificate.setActive(true);
            newCertificate.setSerialNumber(outCertificate.getSerialNumber().toString());
            newCertificate.setIssuer(outCertificate.getIssuerDN().getName());
            newCertificate.setSubject(outCertificate.getSubjectDN().getName());
            newCertificate.setCertFilePath(paths[0]);
            newCertificate.setTrustFilePath(paths[1]);
            newCertificate.setCA(certificateType == CertificateType.INTERMEDIATE);
            newCertificate.setIssuerId(issuerCertificate.getId());

            certificateRepository.save(newCertificate);


        } catch (IOException |
                CertificateException |
                InvalidKeyException |
                SignatureException |
                NoSuchAlgorithmException |
                NoSuchProviderException e) {
            throw new PKIMalfunctionException("Error while creating new root certificate");
        }
    }

    @Override
    public ArrayList<Certificate> findAll() {
        return (ArrayList<Certificate>) certificateRepository.findAll();
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
