package com.businesssystemssecurity.proj.web.controller;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.domain.helper.CertificateType;
import com.businesssystemssecurity.proj.exception.PKIMalfunctionException;
import com.businesssystemssecurity.proj.service.CertificateService;
import com.businesssystemssecurity.proj.web.dto.certificate.CertificateDTO;
import com.businesssystemssecurity.proj.web.dto.certificate.CertificateRequestDTO;
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

    @RequestMapping(value = "/{id}",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAuthority('admin')")
    public ResponseEntity<CertificateDTO> getById(@PathVariable int id) {
        return new ResponseEntity<>(
                new CertificateDTO(certificateService.findById(id)),
                HttpStatus.OK);
    }

    @RequestMapping(value = "/{id}/zip",
            method = RequestMethod.GET,
            produces="application/zip")
    @PreAuthorize("hasAuthority('admin')")
    public byte[] getZip(HttpServletResponse response, @PathVariable int id) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.addHeader("Content-Disposition", "attachment; filename=\"test.zip\"");

        Certificate c = certificateService.findById(id);

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


    @RequestMapping(value = "/test/validate/{serialNumber}",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CertificateDTO> validate(@PathVariable String serialNumber) {

        Certificate c = this.certificateService.findBySerialNumber(serialNumber);

        return new ResponseEntity<>(new CertificateDTO(c), HttpStatus.OK);
    }



}
