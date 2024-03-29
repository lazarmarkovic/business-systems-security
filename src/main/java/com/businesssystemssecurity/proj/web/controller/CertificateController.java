package com.businesssystemssecurity.proj.web.controller;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.exception.AccessDeniedException;
import com.businesssystemssecurity.proj.exception.PKIMalfunctionException;
import com.businesssystemssecurity.proj.security.service.AuthService;
import com.businesssystemssecurity.proj.seeder.data.PermissionTableSeed;
import com.businesssystemssecurity.proj.service.CertificateService;
import com.businesssystemssecurity.proj.web.dto.certificate.CertificateDTO;
import com.businesssystemssecurity.proj.web.dto.certificate.CertificateGenerateRequestDTO;
import com.businesssystemssecurity.proj.web.dto.certificate.CertificateRevokeRequestDTO;
import com.businesssystemssecurity.proj.web.dto.tree.TreeItem;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private AuthService authService;

    @RequestMapping(value = "/{id}",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    public ResponseEntity<CertificateDTO> getById(@PathVariable int id) {
        if (!(this.authService.hasPermission(PermissionTableSeed.ISSUE_ROOT_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_INTERMEDIATE_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_USER_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_ROOT_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_INTERMEDIATE_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_USER_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.REVOKE_ROOT_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.REVOKE_INTERMEDIATE_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.REVOKE_USER_CERTIFICATE))) {
            throw new AccessDeniedException("User has no permission to view certificates.");
        }
        return new ResponseEntity<>(
                new CertificateDTO(certificateService.findById(id)),
                HttpStatus.OK);
    }

    @RequestMapping(value = "/{serialNumber}/zip",
            method = RequestMethod.GET,
            produces="application/zip")
    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    public byte[] getZip(HttpServletResponse response, @PathVariable String serialNumber) {
        if (!(this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_ROOT_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_INTERMEDIATE_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_USER_CERTIFICATE))) {
            throw new AccessDeniedException("User has no permission to view certificates.");
        }

        response.setStatus(HttpServletResponse.SC_OK);
        response.addHeader("Content-Disposition", "attachment; filename=\"test.zip\"");

        Certificate c = certificateService.findBySerialNumber(serialNumber);
        try {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(byteArrayOutputStream);
        ZipOutputStream zipOutputStream = new ZipOutputStream(bufferedOutputStream);

        ArrayList<File> files = new ArrayList<>();
        files.add(new File(c.getCertFilePath()));
        files.add(new File(c.getKeyStoreFilePath()));
        files.add(new File(c.getTrustStoreFilePath()));

        for (File file : files) {
            zipOutputStream.putNextEntry(new ZipEntry(file.getName()));

            FileInputStream fileInputStream = new FileInputStream(file);

            IOUtils.copy(fileInputStream, zipOutputStream);

            fileInputStream.close();
            zipOutputStream.closeEntry();
        }

        if (zipOutputStream != null) {
            zipOutputStream.finish();
            zipOutputStream.flush();
            IOUtils.closeQuietly(zipOutputStream);
        }
        IOUtils.closeQuietly(bufferedOutputStream);
        IOUtils.closeQuietly(byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();

        } catch (IOException e) {
            e.printStackTrace();
            throw new PKIMalfunctionException("Cannot download specified files. Non-existent or corrupted.");
        }
    }

    @RequestMapping(value = "/all",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    public ResponseEntity<ArrayList<Certificate>> getAll() {
        if (!(this.authService.hasPermission(PermissionTableSeed.ISSUE_ROOT_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_INTERMEDIATE_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_USER_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_ROOT_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_INTERMEDIATE_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_USER_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.REVOKE_ROOT_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.REVOKE_INTERMEDIATE_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.REVOKE_USER_CERTIFICATE))) {
            throw new AccessDeniedException("User has no permission to view certificates.");
        }
        return new ResponseEntity<>(
                certificateService.findAll(),
                HttpStatus.OK);
    }

    @RequestMapping(value = "/forest",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    public ResponseEntity<ArrayList<TreeItem>> getForest() {
        if (!(this.authService.hasPermission(PermissionTableSeed.ISSUE_ROOT_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_INTERMEDIATE_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_USER_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_ROOT_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_INTERMEDIATE_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.DISTRIBUTE_USER_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.REVOKE_ROOT_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.REVOKE_INTERMEDIATE_CERTIFICATE) ||
                this.authService.hasPermission(PermissionTableSeed.REVOKE_USER_CERTIFICATE))) {
            throw new AccessDeniedException("User has no permission to view certificates.");
        }
        return new ResponseEntity<>(
                certificateService.getTree(),
                HttpStatus.OK);
    }


    @RequestMapping(value = "",
            method = RequestMethod.POST,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    public ResponseEntity<CertificateDTO> generate(@RequestBody CertificateGenerateRequestDTO request) {
        if (!(this.authService.hasPermission(PermissionTableSeed.ISSUE_ROOT_CERTIFICATE) && request.getCertificateType() == CertificateType.ROOT ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_INTERMEDIATE_CERTIFICATE) && request.getCertificateType() == CertificateType.INTERMEDIATE ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_USER_CERTIFICATE) && request.getCertificateType() == CertificateType.USER)) {
            throw new AccessDeniedException("User has no permission to issue " + request.getCertificateType().name() + " certificates.");
        }

        String serialNumber = "";
        if (request.getCertificateType() != CertificateType.ROOT) {
            Certificate issuer = this.certificateService.findBySerialNumber(request.getIssuerSerialNumber());
            serialNumber = issuer.getSerialNumber();
        }
        Certificate c = certificateService.createCertificate(
                request.getSubjectDTO(),
                serialNumber,
                request.getCertificateType()
        );

        return new ResponseEntity<>(new CertificateDTO(c), HttpStatus.OK);
    }


    @RequestMapping(value = "/revoke",
            method = RequestMethod.POST,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    public ResponseEntity<CertificateDTO> revoke(@RequestBody CertificateRevokeRequestDTO request) {
        Certificate cc = this.certificateService.findBySerialNumber(request.getSerialNumber());
        if (!(this.authService.hasPermission(PermissionTableSeed.ISSUE_ROOT_CERTIFICATE) && cc.getType().equals(CertificateType.ROOT.name()) ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_INTERMEDIATE_CERTIFICATE) && cc.getType().equals(CertificateType.INTERMEDIATE.name()) ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_USER_CERTIFICATE) && cc.getType().equals(CertificateType.USER.name()))) {
            throw new AccessDeniedException("User has no permission to revoke/unrevoke " + cc.getType() + " certificates.");
        }
        Certificate c = certificateService.revokeCertificate(
                request.getSerialNumber(),
                request.getReason()
        );

        return new ResponseEntity<>(new CertificateDTO(c), HttpStatus.OK);
    }


    @RequestMapping(value = "/{serialNumber}/unrevoke",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    public ResponseEntity<CertificateDTO> unrevoke(@PathVariable String serialNumber) {
        Certificate cc = this.certificateService.findBySerialNumber(serialNumber);
        if (!(this.authService.hasPermission(PermissionTableSeed.ISSUE_ROOT_CERTIFICATE) && cc.getType().equals(CertificateType.ROOT.name()) ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_INTERMEDIATE_CERTIFICATE) && cc.getType().equals(CertificateType.INTERMEDIATE.name()) ||
                this.authService.hasPermission(PermissionTableSeed.ISSUE_USER_CERTIFICATE) && cc.getType().equals(CertificateType.USER.name()))) {
            throw new AccessDeniedException("User has no permission to revoke/unrevoke " + cc.getType() + " certificates.");
        }
        Certificate c = certificateService.unrevokeCertificate(serialNumber);
        return new ResponseEntity<>(new CertificateDTO(c), HttpStatus.OK);
    }


}
