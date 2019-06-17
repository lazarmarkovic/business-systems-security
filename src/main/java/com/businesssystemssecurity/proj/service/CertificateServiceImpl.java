package com.businesssystemssecurity.proj.service;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificatesAndKeyHolder;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.exception.EntityNotFoundException;
import com.businesssystemssecurity.proj.exception.PKIMalfunctionException;
import com.businesssystemssecurity.proj.repository.CertificateRepository;
import com.businesssystemssecurity.proj.storage.CertificateStorage;
import com.businesssystemssecurity.proj.web.dto.tree.TreeItem;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
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

@Service
public class CertificateServiceImpl implements CertificateService {

    @Autowired
    private CertificateStorage certificateStorage;

    @Autowired
    private CertificateRepository certificateRepository;

    @Value( "${pki.key-alias}" )
    private String keyStoreAliasName;

    @Value( "${pki.key-store-password}" )
    private char[] keyStorePassword;

    @Value( "${pki.trust-store-password}" )
    private char[] trustStorePassword;

    @Override
    @Transactional
    public Certificate createRootCertificate(String subject) {
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
            c.setCertFilePath(paths[0]);
            c.setKeyStoreFilePath(paths[1]);
            c.setTrustStoreFilePath(paths[2]);
            c.setCA(true);
            c.setActive(true);
            c.setType(CertificateType.ROOT.toString());

            certificateRepository.save(c);
            return c;


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
    public Certificate createSignedCertificate(String subject, String issuer, CertificateType certificateType) {
        Optional<Certificate> opt = certificateRepository.findBySubject(issuer);
        Certificate issuerCertificate = opt.orElseThrow(() -> new EntityNotFoundException(Certificate.class, "issuer", issuer));

        Certificate c = certificateRepository.findBySerialNumber(issuerCertificate.getSerialNumber()).get();
        /* Check if can extend chain */
        if (c.getType().equals(CertificateType.ROOT.toString()) && certificateType == CertificateType.USER) {
            throw new PKIMalfunctionException("USER cert cannot be directly issued by ROOT cert.");
        }

        if (c.getType().equals(CertificateType.USER.toString())) {
            throw new PKIMalfunctionException("Cert cannot be issued by USER.");
        }

        CertificatesAndKeyHolder ckh = certificateStorage.loadPrivateKeyAndChain(
                issuerCertificate.getKeyStoreFilePath(),
                issuerCertificate.getSerialNumber().toString(),
                this.keyStorePassword);

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
            newCertificate.setKeyStoreFilePath(paths[1]);
            newCertificate.setTrustStoreFilePath(paths[2]);
            newCertificate.setCA(certificateType == CertificateType.INTERMEDIATE);
            newCertificate.setType(certificateType.toString());

            certificateRepository.save(newCertificate);
            return newCertificate;

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

    @Override
    public Certificate findById(int id) {
        Optional<Certificate> opt = this.certificateRepository.findById((long) id);
        return opt.orElseThrow(() -> new EntityNotFoundException(Certificate.class, "id", Long.toString(id)));    }


    @Override
    public ArrayList<Certificate> findAll() {
        return (ArrayList<Certificate>) certificateRepository.findAll();
    }

    @Override
    public ArrayList<TreeItem> getTree() {
        ArrayList<Certificate> certs = this.findAll();
        ArrayList<TreeItem> forest = new ArrayList<>();

        for (Certificate c : certs) {
            if (c.getSubject().equals(c.getIssuer())) {
                TreeItem ti = new TreeItem(c.getId(), c.getSubject());
                forest.add(ti);
            } else {
                this.addToForest(c, forest);
            }
        }

        return forest;
    }

    private void addToForest(Certificate cert,  ArrayList<TreeItem> forest) {
        if (forest.size() == 0) {
            return;
        }

        for (TreeItem ti : forest)  {
            if (ti.getName().equals(cert.getIssuer())) {
                TreeItem treeToAdd = new TreeItem(cert.getId(), cert.getSubject());
                ti.getChildren().add(treeToAdd);
            } else {
                addToForest(cert, ti.getChildren());
            }
        }
    }

}
