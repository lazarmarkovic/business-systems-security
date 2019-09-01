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
import java.util.List;
import java.util.Optional;

@Service
public class CertificateServiceImpl implements CertificateService {

    @Autowired
    private CertificateStorage certificateStorage;

    @Autowired
    private CertificateRepository certificateRepository;

    @Value( "${pki.key-store-password}" )
    private char[] keyStorePassword;

    @Value( "${pki.trust-store-password}" )
    private char[] trustStorePassword;

    @Override
    @Transactional
    public Certificate createRootCertificate(String subject) {
        CertAndKeyGen gen = generateKeyPair();
        //CertificateExtensions certificateExtensions = this.setOCSPExtension(new CertificateExtensions());
        CertificateExtensions certificateExtensions = new CertificateExtensions();
        X500Principal x500Subject = new X500Principal(subject);

        try {
            certificateExtensions.set(
                    BasicConstraintsExtension.NAME,
                    new BasicConstraintsExtension(true, -1)
            );
            X509Certificate outCertificate = gen.getSelfCertificate(
                    X500Name.asX500Name(x500Subject),
                    new Date(),
                    (long) 365 * 24 * 3600,
                    certificateExtensions
            );

            CertificatesAndKeyHolder certificatesAndKeyHolder = new CertificatesAndKeyHolder();
            certificatesAndKeyHolder.setChain(new X509Certificate[]{outCertificate});
            certificatesAndKeyHolder.setPrivateKey(gen.getPrivateKey());

            System.out.println("Started storing certificate.");
            String[] paths = certificateStorage.storeCertificate(certificatesAndKeyHolder, CertificateType.ROOT);
            System.out.println("Finished storing certificate.");
            return saveCertificateInfoToDatabase(
                    outCertificate,
                    CertificateType.ROOT,
                    paths
            );

        } catch (IOException |
                CertificateException |
                InvalidKeyException |
                SignatureException |
                NoSuchAlgorithmException |
                NoSuchProviderException e) {
            throw new PKIMalfunctionException("Error while creating new root-certificate");
        }
    }

    @Override
    @Transactional
    public Certificate createSignedCertificate(String subject, String issuer, CertificateType certificateType) {
        Optional<Certificate> opt = certificateRepository.findBySubject(issuer);
        Certificate issuerCertificate = opt.orElseThrow(() -> new EntityNotFoundException(Certificate.class, "issuer", issuer));

        /* Check if can extend chain */
        if (issuerCertificate.getType().equals(CertificateType.ROOT.toString()) && certificateType == CertificateType.USER) {
            throw new PKIMalfunctionException("USER cert cannot be directly issued by ROOT cert.");
        }

        if (issuerCertificate.getType().equals(CertificateType.USER.toString())) {
            throw new PKIMalfunctionException("Cert cannot be issued by USER.");
        }

        CertificatesAndKeyHolder ckh = certificateStorage.loadPrivateKeyAndChain(
                issuerCertificate.getKeyStoreFilePath(),
                issuerCertificate.getSerialNumber(),
                this.keyStorePassword
        );

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

            //CertificateExtensions certificateExtensions = this.setOCSPExtension(new CertificateExtensions());
            CertificateExtensions certificateExtensions = new CertificateExtensions();

            if (certificateType == CertificateType.USER) {
                certificateExtensions.set(
                        BasicConstraintsExtension.NAME,
                        new BasicConstraintsExtension(false, -1)
                );
            } else {
                certificateExtensions.set(
                        BasicConstraintsExtension.NAME,
                        new BasicConstraintsExtension(true, -1)
                );
            }
            info.set(X509CertInfo.EXTENSIONS, certificateExtensions);
            X509CertImpl outCertificate = new X509CertImpl(info);
            outCertificate.sign(ckh.getPrivateKey(), issuerSigAlg);

            ckh.addToBeginning(outCertificate);

            System.out.println("Started storing certificate.");
            String[] paths = certificateStorage.storeCertificate(ckh, certificateType);
            System.out.println("Finished storing certificate.");

            return saveCertificateInfoToDatabase(
                    outCertificate,
                    certificateType,
                    paths
            );

        } catch (IOException |
                CertificateException |
                InvalidKeyException |
                SignatureException |
                NoSuchAlgorithmException |
                NoSuchProviderException e) {
            e.printStackTrace();
            throw new PKIMalfunctionException("Error while creating new sub-certificate");
        }
    }

    private Certificate saveCertificateInfoToDatabase(
            X509Certificate x509Certificate,
            CertificateType certificateType,
            String[] paths) {
        Certificate newCertificate = new Certificate();
        newCertificate.setSerialNumber(x509Certificate.getSerialNumber().toString());
        newCertificate.setIssuer(x509Certificate.getIssuerDN().getName());
        newCertificate.setSubject(x509Certificate.getSubjectDN().getName());
        newCertificate.setCertFilePath(paths[0]);
        newCertificate.setKeyStoreFilePath(paths[1]);
        newCertificate.setTrustStoreFilePath(paths[2]);
        newCertificate.setCA(certificateType != CertificateType.USER);
        newCertificate.setType(certificateType.toString());
        newCertificate.setRevoked(false);
        newCertificate.setRevokedAt(null);
        newCertificate.setRevokeReason(null);
        certificateRepository.save(newCertificate);
        return newCertificate;
    }

    /* Add OCSP responder's URI to certificate as extension */
    private CertificateExtensions setOCSPExtension(CertificateExtensions certificateExtensions) {
        try{
            List<AccessDescription> accessDescriptions = new ArrayList<>();
            GeneralNameInterface responderURL = new URIName("http://localhost:8085/verify");
            GeneralName generalName = new GeneralName(responderURL);
            AccessDescription OCSPAccessDescription = new AccessDescription(
                    AccessDescription.Ad_OCSP_Id,
                    generalName);
            accessDescriptions.add(OCSPAccessDescription);
            certificateExtensions.set(
                    AuthorityInfoAccessExtension.NAME,
                    new AuthorityInfoAccessExtension(accessDescriptions)
            );

            return certificateExtensions;

        } catch (IOException e) {
            e.printStackTrace();
            throw new PKIMalfunctionException("Cannot add OCSP extension to the certificate");
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
    public Certificate findBySerialNumber(String serialNumber) {
        Optional<Certificate> opt = this.certificateRepository.findBySerialNumber(serialNumber);
        return opt.orElseThrow(() -> new EntityNotFoundException(Certificate.class, "serialNumber", serialNumber));
    }

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
