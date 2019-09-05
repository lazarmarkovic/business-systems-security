package com.businesssystemssecurity.proj.OCSP.responder;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificatesAndKeyHolder;
import com.businesssystemssecurity.proj.service.CertificateService;
import com.businesssystemssecurity.proj.storage.CertificateStorage;
import lombok.extern.slf4j.Slf4j;
import net.maritimecloud.pki.Revocation;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.security.KeyStore;
import java.util.Date;


@RestController
@Slf4j
public class ResponderController {

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private KeystoreHandler keystoreHandler;

    @Autowired
    private CertificateStorage certificateStorage;

    public static final String SIGNER_ALGORITHM = "SHA1withRSA";
    public static final String BC_PROVIDER_NAME = "BC";

    private static BouncyCastleProvider bouncyCastleProvider;
    public static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();
    static {
        bouncyCastleProvider = BOUNCY_CASTLE_PROVIDER;
    }


    @RequestMapping(
            value = "/verify/{caAlias}",
            method = RequestMethod.POST,
            consumes = "application/ocsp-request",
            produces = "application/ocsp-response")
    @ResponseBody
    public ResponseEntity<?> postOCSP(@PathVariable String caAlias, @RequestBody byte[] input) {
        System.out.println("Enter POST.");
        byte[] byteResponse;
        try {
            byteResponse = handleOCSP(input, caAlias);
            System.out.println("Finish handling");
        } catch (Exception e) {
            e.printStackTrace();
            //log.error("Failed to update OCSP", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(byteResponse, HttpStatus.OK);
    }

    @RequestMapping(
            value = "/verify/{caAlias}/**",
            method = RequestMethod.GET,
            produces = "application/ocsp-response")
    @ResponseBody
    public ResponseEntity<?> getOCSP(HttpServletRequest request, @PathVariable String caAlias) {
        System.out.println("Enter GET");
        String uri = request.getRequestURI();
        String encodedOCSP = uri.substring(uri.indexOf(caAlias) + caAlias.length() + 1);
        try {
            encodedOCSP = URLDecoder.decode(encodedOCSP, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            log.error("Failed to URL decode OCSP", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        byte[] decodedOCSP = Base64.decode(encodedOCSP);
        byte[] byteResponse;
        try {
            byteResponse = handleOCSP(decodedOCSP, caAlias);
        } catch (Exception e) {
            e.printStackTrace();
            log.error("Failed to base64 decode OCSP", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(byteResponse, HttpStatus.OK);
    }

    // CertAlas - is alias for certificate that signed given certificate to be validated by responder
    // cert.getCA() - needs to return serial number of issuer (add field to database :(() (done)
    // OCSP responder need to have access to PKI Systems keystores and so on.... (done)


    protected byte[] handleOCSP(byte[] input, String certAlias) throws Exception {
        OCSPReq ocspreq = new OCSPReq(input);
        System.out.println("Assemble request from input.");

        /* TODO: verify signature - needed?
        if (ocspreq.isSigned()) {
        }*/

        BasicOCSPRespBuilder respBuilder = Revocation.initOCSPRespBuilder(ocspreq, this.keystoreHandler.getMCCertificate(certAlias).getPublicKey());
        System.out.println("Assemble response builder");

        Req[] requests = ocspreq.getRequestList();
        for (Req req : requests) {
            BigInteger sn = req.getCertID().getSerialNumber();
            Certificate cert = this.certificateService.findBySerialNumber(sn.toString());

            if (cert == null) {
                respBuilder.addResponse(req.getCertID(), new UnknownStatus());

                // Check if the certificate is even signed by this CA
            } else if (!certAlias.equals(cert.getCaSerialNumber())) {
                respBuilder.addResponse(req.getCertID(), new UnknownStatus());

                // Check if certificate has been revoked
            } else if (cert.getRevoked()) {
                respBuilder.addResponse(req.getCertID(), new RevokedStatus(cert.getRevokedAt(), Revocation.getCRLReasonFromString(cert.getRevokeReason())));

            } else {
                // Certificate is valid
                respBuilder.addResponse(req.getCertID(), CertificateStatus.GOOD);
            }
        }
        System.out.println("Assemble responses array");

        OCSPResp response = null;

        KeyStore.PrivateKeyEntry privateKeyEntry = this.keystoreHandler.getSigningCertEntry(certAlias);

        Certificate certificate = this.certificateService.findBySerialNumber(certAlias);
        CertificatesAndKeyHolder ckh = this.certificateStorage.getPrivateKeyAndChain(certificate.getKeyStoreFilePath(), certAlias);

        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNER_ALGORITHM).setProvider(BC_PROVIDER_NAME).build(ckh.getPrivateKey());
            BasicOCSPResp basicResp = respBuilder.build(contentSigner,
                    new X509CertificateHolder[] { new X509CertificateHolder(ckh.getChain()[0].getEncoded()) }, new Date());
            // build the response
            response = new OCSPRespBuilder().build( OCSPRespBuilder.SUCCESSFUL, basicResp);
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (response == null) {
            System.out.println("Response is null.");
        }
        byte[] resp = response.getEncoded();
        System.out.println("Assemble final encoded response.");
        return resp;


    }
}