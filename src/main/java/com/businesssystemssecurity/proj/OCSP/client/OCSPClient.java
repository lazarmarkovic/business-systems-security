package com.businesssystemssecurity.proj.OCSP.client;


import net.maritimecloud.pki.PKIConstants;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;


public class OCSPClient {

    @Value("${pki.ocsp-responder.truststore.resource}")
    private Resource signingCATrustStoreResource;
    @Value("${pki.ocsp-responder.truststore.password}")
    private char[] signingCATrustStorePassword;
    @Value("${pki.ocsp-responder.truststore.type}")
    private String signingCATrustStoreType;

    private static byte[] sentNonce;
    private final X509Certificate issuer;
    private final X509Certificate certificate;
    private URL url;
    private RevokedStatus revokedStatus = null;

    public OCSPClient(X509Certificate issuer, X509Certificate certificate) {
        this.issuer = issuer;
        this.certificate = certificate;
        this.url = getOcspUrlFromCertificate(certificate);
    }

    private OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws CertificateEncodingException, OperatorCreationException, OCSPException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(new JcaDigestCalculatorProviderBuilder().setProvider(PKIConstants.BC_PROVIDER_NAME).build().get(CertificateID.HASH_SHA1), issuerCert, serialNumber));

        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, new DEROctetString(nonce.toByteArray()));
        gen.setRequestExtensions(new Extensions(new Extension[]{ext}));
        sentNonce = ext.getExtnId().getEncoded();

        return gen.build();
    }

    /* Is not mandatory, but CC certificates have */
    public static URL getOcspUrlFromCertificate(X509Certificate certificate) {
        byte[] octetBytes = certificate.getExtensionValue(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess.getId());
        URL url = null;
        if (null != octetBytes) {
            try {
                byte[] encoded = X509ExtensionUtil.fromExtensionValue(octetBytes).getEncoded();
                ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoded));
                AuthorityInformationAccess access = AuthorityInformationAccess.getInstance(seq);
                for (AccessDescription accessDescription : access.getAccessDescriptions()){
                    if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_ocsp)){
                        url = new URL(accessDescription.getAccessLocation().getName().toString());
                        break;
                    }
                }
            } catch (IOException ignore) {
            }
        }
        return url;
    }


    public Optional<RevokedStatus> getRevokedStatus(){
        return Optional.ofNullable(revokedStatus);
    }


    public CertStatus getCertificateStatus() throws OCSPValidationException {
        try {
            if (null == url) {
                throw new OCSPValidationException("Certificate not validated by OCSP");
            }

            byte[] encodedOcspRequest = generateOCSPRequest(issuer, certificate.getSerialNumber()).getEncoded();

            HttpURLConnection httpConnection;
            httpConnection = (HttpURLConnection) url.openConnection();
            httpConnection.setRequestProperty("Content-Type", "application/ocsp-request");
            httpConnection.setRequestProperty("Accept", "application/ocsp-response");
            httpConnection.setDoOutput(true);

            try (DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(httpConnection.getOutputStream()))) {
                dataOut.write(encodedOcspRequest);
                dataOut.flush();
            }

            InputStream in = (InputStream) httpConnection.getContent();

            if (httpConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new OCSPValidationException("Received HTTP code != 200 ["+httpConnection.getResponseCode()+"]");
            }

            OCSPResp ocspResponse = new OCSPResp(in);
            BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();

            byte[] receivedNonce = basicResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnId().getEncoded();
            if (!Arrays.equals(receivedNonce, sentNonce)) {
                throw new OCSPValidationException("Nonce in ocsp response does not match nonce of ocsp request");
            }

            X509CertificateHolder certHolder = basicResponse.getCerts()[0];
            if (!basicResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(issuer))){
                if (!certHolder.isValidOn(Date.from(Instant.now()))){
                    throw new OCSPValidationException("Certificate is not valid today!");
                }
                // Certificate must have a Key Purpose ID for authorized responders
                if (!ExtendedKeyUsage.fromExtensions(certHolder.getExtensions()).hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning)){
                    throw new OCSPValidationException("Certificate does not contain required extension (id_kp_OCSPSigning)");
                }
                // Certificate must be issued by the same CA of the certificate that we are verifying
                if (!certHolder.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(issuer))){
                    throw new OCSPValidationException("Certificate is not signed by the same issuer");
                }
                // Validate signature in OCSP response
                if (!basicResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(certHolder))){
                    throw new OCSPValidationException("Could not validate OCSP response!");
                }
            } else {
                if (!certHolder.isValidOn(Date.from(Instant.now()))){
                    throw new OCSPValidationException("Certificate is not valid today!");
                }
            }

            // SCEE Certificate Policy (?)
            /*if (null == certHolder.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck) || null == certHolder.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck).getExtnId()) {
                throw new OCSPValidationException("Extension id_pkix_ocsp_nocheck not found in certificate");
            }*/

            SingleResp[] responses = basicResponse.getResponses();
            if (responses[0].getCertID().getSerialNumber().equals(certificate.getSerialNumber())) {
                CertificateStatus status = responses[0].getCertStatus();
                if (status == CertificateStatus.GOOD) {
                    return CertStatus.GOOD;
                } else {

                    if (status instanceof RevokedStatus) {
                        revokedStatus = (RevokedStatus) status;
                        return CertStatus.REVOKED;
                    } else {
                        return CertStatus.UNKNOWN;
                    }
                }
            } else {
                throw new OCSPValidationException("Serial number of certificate in response ocsp does not match certificate serial number");
            }
        } catch (OperatorCreationException |
                OCSPException |
                IOException |
                CertException |
                CertificateException ex) {
            ex.printStackTrace();
            throw new OCSPValidationException("Unable to perform validation through OCSP (" + certificate.getSubjectX500Principal().getName() + ")", ex);
        }
    }


    public boolean checkOCSP() throws OCSPValidationException {
        try {
            return getCertificateStatus() == CertStatus.GOOD;
        } catch (OCSPValidationException ex) {
            return false;
        }
    }
}

