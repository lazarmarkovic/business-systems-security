package com.businesssystemssecurity.proj.OCSP.responder;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.service.CertificateService;
import lombok.extern.slf4j.Slf4j;
import net.maritimecloud.pki.Revocation;
import org.bouncycastle.cert.ocsp.*;
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


@RestController
@RequestMapping(value={"/api"})
@Slf4j
public class ResponderController {

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private KeystoreHandler keystoreHandler;


    @RequestMapping(
            value = "/verify/{caAlias}",
            method = RequestMethod.POST,
            consumes = "application/ocsp-request",
            produces = "application/ocsp-response")
    @ResponseBody
    public ResponseEntity<?> postOCSP(@PathVariable String caAlias, @RequestBody byte[] input) {
        byte[] byteResponse;
        try {
            byteResponse = handleOCSP(input, caAlias);
        } catch (IOException e) {
            log.error("Failed to update OCSP", e);
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
        String uri = request.getRequestURI();
        String encodedOCSP = uri.substring(uri.indexOf(caAlias) + caAlias.length() + 1);
        try {
            encodedOCSP = URLDecoder.decode(encodedOCSP, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            log.error("Failed to URL decode OCSP", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        byte[] decodedOCSP = Base64.decode(encodedOCSP);
        byte[] byteResponse;
        try {
            byteResponse = handleOCSP(decodedOCSP, caAlias);
        } catch (IOException e) {
            log.error("Failed to base64 decode OCSP", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(byteResponse, HttpStatus.OK);
    }

    // CertAlas - is alias for certificate that signed given certificate to be validated by responder
    // cert.getCA() - needs to return serial number of issuer (add field to database :(() (done)
    // OCSP responder need to have access to PKI Systems keystores and so on.... (done)


    protected byte[] handleOCSP(byte[] input, String certAlias) throws IOException {
        OCSPReq ocspreq = new OCSPReq(input);
        /* TODO: verify signature - needed?
        if (ocspreq.isSigned()) {
        }*/
        BasicOCSPRespBuilder respBuilder = Revocation.initOCSPRespBuilder(ocspreq, this.keystoreHandler.getMCCertificate(certAlias).getPublicKey());
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
        OCSPResp response = Revocation.generateOCSPResponse(respBuilder, this.keystoreHandler.getSigningCertEntry(certAlias));
        return response.getEncoded();
    }
}