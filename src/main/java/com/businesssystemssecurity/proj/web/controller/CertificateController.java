package com.businesssystemssecurity.proj.web.controller;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.service.CertificateService;
import com.businesssystemssecurity.proj.web.dto.certificate.CertificateRequestDTO;
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


    @GetMapping
    @PreAuthorize("hasAuthority('admin')")
    public ResponseEntity<ArrayList<Certificate>> getAll() {
        return new ResponseEntity<>(
                certificateService.findAll(),
                HttpStatus.OK);
    }


    @PostMapping(produces = MediaType.TEXT_PLAIN_VALUE)
    @PreAuthorize("hasAuthority('admin')")
    public ResponseEntity<String> generate(@RequestBody CertificateRequestDTO request) {

        if (request.getCertificateType() == CertificateType.ROOT) {
            certificateService.createRootCertificate(request.getSubject());
            return new ResponseEntity<>("ROOT certificate successfully created!", HttpStatus.OK);

        } else {
            certificateService.createSignedCertificate(
                    request.getSubject(),
                    request.getIssuer(),
                    request.getCertificateType()
            );

        }
        return new ResponseEntity<>("INTER or USER certificate successfully created!", HttpStatus.OK);
    }


}
