package com.businesssystemssecurity.proj.service;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.domain.helper.CertificatesAndKeyHolder;
import com.businesssystemssecurity.proj.domain.helper.IssuerData;
import com.businesssystemssecurity.proj.domain.helper.SubjectData;
import com.businesssystemssecurity.proj.exception.EntityNotFoundException;
import com.businesssystemssecurity.proj.exception.PKIMalfunctionException;
import com.businesssystemssecurity.proj.repository.CertificateRepository;
import com.businesssystemssecurity.proj.storage.CertificateStorage;
import com.businesssystemssecurity.proj.web.dto.subject.SubjectDTO;
import com.businesssystemssecurity.proj.web.dto.tree.TreeItem;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import sun.security.x509.SubjectAlternativeNameExtension;


import javax.transaction.Transactional;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
public class CertificateServiceImpl implements CertificateService {

    @Autowired
    private CertificateStorage certificateStorage;

    @Autowired
    private CertificateRepository certificateRepository;

    @Value("${pki.key-store-password}")
    private char[] keyStorePassword;

    @Value("${pki.trust-store-password}")
    private char[] trustStorePassword;

    @Value("${pki.certificate.provider}")
    private String provider;

    @Value("${pki.algorithm.signature}")
    private String signatureAlgorithm;

    @Value("${pki.algorithm.key}")
    private String keyAlgorithm;

    @Value("${pki.seed.algorithm}")
    private String seedAlgorithm;

    @Value("${pki.seed.provider}")
    private String seedProvider;

    @Value("${pki.ocsp.responder-server-url}")
    private String OCSPResponderServerURL;

    @Value("${pki.ca.keysize}")
    private int caKeySize;

    @Value("${pki.user.keysize}")
    private int userKeySize;

    @Override
    public Certificate findById(int id) {
        Optional<Certificate> opt = this.certificateRepository.findById((long) id);
        return opt.orElseThrow(() -> new EntityNotFoundException(Certificate.class, "id", Long.toString(id)));
    }

    @Override
    public Certificate findBySerialNumber(String serialNumber) {
        Optional<Certificate> opt = this.certificateRepository.findBySerialNumber(serialNumber);
        return opt.orElseThrow(() -> new EntityNotFoundException(Certificate.class, "serialNumber", serialNumber));
    }

    @Override
    public Certificate findBySubjectName(String subjectName) {
        Optional<Certificate> opt = this.certificateRepository.findBySubject(subjectName);
        return opt.orElseThrow(() -> new EntityNotFoundException(Certificate.class, "subjectName", subjectName));
    }

    @Override
    public ArrayList<Certificate> findAll() {
        return (ArrayList<Certificate>) certificateRepository.findAll();
    }

    /*-------------------------------------------------------------------------------------------*/

    @Override
    @Transactional
    public Certificate createCertificate(SubjectDTO subjectDTO, String issuerSerialNumber, CertificateType type) {

        X500Name subjectDN = this.subjectDTOToX500Name(subjectDTO);
        KeyPair keyPair;
        SubjectData subject;
        IssuerData issuer;
        X509Certificate certificate;

        if (type == CertificateType.ROOT) {
            keyPair = generateKeyPair(true);
            subject = generateSubjectData(keyPair.getPublic(), subjectDN, true);
            issuer = new IssuerData(keyPair.getPrivate(), subjectDN, subject.getPublicKey(), subject.getSerialNumber());
            certificate = generateCertificate(subject, issuer, true);
        }
        else if (type == CertificateType.INTERMEDIATE) {
            keyPair = generateKeyPair(true);
            subject = generateSubjectData(keyPair.getPublic(), subjectDN, true);
            issuer = this.certificateStorage.getIssuerDataBySerialNumber(issuerSerialNumber);
            certificate = generateCertificate(subject, issuer, true);
        }
        else {
            keyPair = generateKeyPair(false);
            issuer = this.certificateStorage.getIssuerDataBySerialNumber(issuerSerialNumber);
            subject = generateSubjectData(keyPair.getPublic(), subjectDN, false);
            certificate = generateCertificate(subject, issuer, false);
        }

        /* Store certificate chain to local keystore */
        this.certificateStorage.storeCertificateChan(new X509Certificate[]{certificate}, keyPair.getPrivate());

        /* Create distribution here */
        String[] filePathsOfDistributionFiles = this.certificateStorage.storeCertificateDistributionFiles(
                certificate.getSerialNumber().toString(),
                type
        );

        Certificate c = new Certificate(
                subject.getSerialNumber().toString(),
                issuer.getSerialNumber().toString(),
                type.toString(),
                certificate.getIssuerDN().toString(),
                certificate.getSubjectDN().toString(),
                type != CertificateType.USER,
                filePathsOfDistributionFiles[0],
                filePathsOfDistributionFiles[1],
                filePathsOfDistributionFiles[2],
                false,
                null,
                null
        );

//        /* Test their method */
//        Path pathToKeyStore = Paths.get("src", "main", "resources", "keystore", "TheKeyStore.p12");
//        CertificatesAndKeyHolder ckh = this.certificateStorage.getPrivateKeyAndChain(
//                pathToKeyStore.toString(),
//                certificate.getSerialNumber().toString()
//        );
//
//
//        Path pathToTestKeyStore = Paths.get("src", "main", "resources", "keystore", "TESTKeyStoreSUB.p12");
//        Path pathToTestTrustStore = Paths.get("src", "main", "resources", "keystore", "TESTTrustStoreSUB.p12");
//        this.certificateStorage.createKeyStoreTest(
//                pathToTestKeyStore,
//                ckh.getChain(),
//                ckh.getPrivateKey()
//        );
//
//        this.certificateStorage.createTrustStoreTest(
//                pathToTestTrustStore,
//                ckh.getChain()[0]
//        );

        certificateRepository.save(c);
        return c;
    }

    private X500Name subjectDTOToX500Name(SubjectDTO subjectDTO) {
        X500NameBuilder nameBuilder = new X500NameBuilder();

        if (!subjectDTO.getCommonName().isEmpty()) {
            nameBuilder.addRDN(BCStyle.CN, subjectDTO.getCommonName());
        }
        if (!subjectDTO.getOrganizationUnit().isEmpty()) {
            nameBuilder.addRDN(BCStyle.OU, subjectDTO.getOrganizationUnit());
        }
        if (!subjectDTO.getOrganization().isEmpty()) {
            nameBuilder.addRDN(BCStyle.O, subjectDTO.getOrganization());
        }
        if (!subjectDTO.getCountry().isEmpty()) {
            nameBuilder.addRDN(BCStyle.C, subjectDTO.getCountry());
        }
        return nameBuilder.build();
    }

    private X509Certificate generateCertificate(SubjectData subjectData, IssuerData issuerData, boolean isCA) {
        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(
                    this.signatureAlgorithm)
                    .setProvider(this.provider).build(issuerData.getPrivateKey());

            X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
                    issuerData.getX500name(),
                    subjectData.getSerialNumber(),
                    subjectData.getStartDate(),
                    subjectData.getEndDate(),
                    subjectData.getX500name(),
                    subjectData.getPublicKey());

            BasicConstraints basicConstraints = new BasicConstraints(isCA);
            v3CertGen.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();

            AuthorityKeyIdentifier authorityKeyIdentifier = extensionUtils
                    .createAuthorityKeyIdentifier(issuerData.getPublicKey());
            v3CertGen.addExtension(new ASN1ObjectIdentifier("2.5.29.35"), false, authorityKeyIdentifier);

            SubjectKeyIdentifier subjectKeyIdentifier = extensionUtils
                    .createSubjectKeyIdentifier(subjectData.getPublicKey());
            v3CertGen.addExtension(new ASN1ObjectIdentifier("2.5.29.14"), false, subjectKeyIdentifier);

            /* Add subject alternative name */
            GeneralName altName = new GeneralName(GeneralName.dNSName, "localhost");
            GeneralNames subjectAltName = new GeneralNames(altName);
            v3CertGen.addExtension(X509Extensions.SubjectAlternativeName, false, subjectAltName);

            /* Add OCSP response server data */
            addAuthorityInformationAccess(issuerData.getSerialNumber().toString(), v3CertGen);

            return new JcaX509CertificateConverter()
                    .setProvider(this.provider)
                    .getCertificate(v3CertGen.build(contentSigner));
        } catch (IllegalArgumentException |
                IllegalStateException |
                OperatorCreationException |
                CertificateException |
                CertIOException |
                NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new PKIMalfunctionException("Error while generating new certificate.");
        }
    }

    private void addAuthorityInformationAccess(String issuerAlias, X509v3CertificateBuilder v3CertGen) throws CertIOException {
        AccessDescription caIssuers = new AccessDescription(
                AccessDescription.id_ad_caIssuers,
                new GeneralName(
                        GeneralName.uniformResourceIdentifier,
                        new DERIA5String(this.OCSPResponderServerURL + issuerAlias)
                )
        );
        ASN1EncodableVector aia_ASN = new ASN1EncodableVector();
        aia_ASN.add(caIssuers);
        v3CertGen.addExtension(Extension.authorityInfoAccess, false, new DERSequence(aia_ASN));
    }

    private SubjectData generateSubjectData(PublicKey publicKey, X500Name subjectDN, boolean isCA) {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();
        return new SubjectData(publicKey, subjectDN, new BigInteger(Long.toString(now)), startDate, endDate);
    }


    private KeyPair generateKeyPair(boolean isCA) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(this.keyAlgorithm);
            SecureRandom random = SecureRandom.getInstance(this.seedAlgorithm, this.seedProvider);
            if (isCA) {
                keyGen.initialize(this.caKeySize, random);
            } else {
                keyGen.initialize(this.userKeySize, random);
            }
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            throw new PKIMalfunctionException("Error while generating new key pair.");
        }
    }

    @Override
    @Transactional
    public ArrayList<TreeItem> getTree() {
        ArrayList<Certificate> certs = this.findAll();
        ArrayList<TreeItem> forest = new ArrayList<>();

        for (Certificate c : certs) {
            if (c.getSubject().equals(c.getIssuer())) {
                TreeItem ti = new TreeItem(c.getId(), c);
                forest.add(ti);
            } else {
                this.addToForest(c, forest);
            }
        }

        return forest;
    }

    private void addToForest(Certificate cert, ArrayList<TreeItem> forest) {
        if (forest.size() == 0) {
            return;
        }

        for (TreeItem ti : forest) {
            if (ti.getCertificate().getSubject().equals(cert.getIssuer())) {
                TreeItem treeToAdd = new TreeItem(cert.getId(), cert);
                ti.getChildren().add(treeToAdd);
            } else {
                addToForest(cert, ti.getChildren());
            }
        }
    }

}
