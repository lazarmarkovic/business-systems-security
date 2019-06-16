package com.businesssystemssecurity.proj.web.controller;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.service.CertificateService;
import com.businesssystemssecurity.proj.web.dto.certificate.CertificateDTO;
import com.businesssystemssecurity.proj.web.dto.certificate.CertificateRequestDTO;
import com.businesssystemssecurity.proj.web.dto.tree.TreeItem;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {

    @Autowired
    private CertificateService certificateService;

    @RequestMapping(value = "/{id}",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAuthority('admin')")
    public ResponseEntity<CertificateDTO> getById(@PathVariable int id) {
        return new ResponseEntity<>(
                new CertificateDTO(certificateService.findById(id)),
                HttpStatus.OK);
    }

    @RequestMapping(value = "/all",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAuthority('admin')")
    public ResponseEntity<ArrayList<Certificate>> getAll() {
        return new ResponseEntity<>(
                certificateService.findAll(),
                HttpStatus.OK);
    }

    @RequestMapping(value = "/forest",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAuthority('admin')")
    public ResponseEntity<ArrayList<TreeItem>> getForest() {
        return new ResponseEntity<>(
                certificateService.getTree(),
                HttpStatus.OK);
    }


    @RequestMapping(value = "",
            method = RequestMethod.POST,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAuthority('admin')")
    public ResponseEntity<CertificateDTO> generate(@RequestBody CertificateRequestDTO request) {

        if (request.getCertificateType() == CertificateType.ROOT) {
            Certificate c = certificateService.createRootCertificate(request.getSubject());
            return new ResponseEntity<>(new CertificateDTO(c), HttpStatus.OK);

        } else {
            Certificate c = certificateService.createSignedCertificate(
                    request.getSubject(),
                    request.getIssuer(),
                    request.getCertificateType()
            );
            return new ResponseEntity<>(new CertificateDTO(c), HttpStatus.OK);
        }
    }


}
