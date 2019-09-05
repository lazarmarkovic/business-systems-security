package com.businesssystemssecurity.proj.web.dto.tree;

import com.businesssystemssecurity.proj.domain.Certificate;
import com.businesssystemssecurity.proj.web.dto.certificate.CertificateDTO;

import java.util.ArrayList;

public class TreeItem {
    private long id;
    private String name;
    private CertificateDTO certificate;
    private ArrayList<TreeItem> children;

    public TreeItem() {
        this.children = new ArrayList<>();
    }

    public TreeItem(long id, Certificate certificate, ArrayList<TreeItem> children) {
        this.id = id;

        /* Extract only common name from subject */
        this.name = certificate.getSubject();
        this.name = this.name.substring(this.name.indexOf("=") + 1);
        this.name = this.name.substring(0, this.name.indexOf(","));

        this.certificate = new CertificateDTO(certificate);
        this.children = children;
    }

    public TreeItem(long id, Certificate certificate) {
        this.id = id;

        /* Extract only common name from subject */
        this.name = certificate.getSubject();
        this.name = this.name.substring(this.name.indexOf("=") + 1);
        this.name = this.name.substring(0, this.name.indexOf(","));

        if (certificate.getRevoked()) {
            this.name += "  [ Status: REVOKED ]";
        } else {
            this.name += "  [ Status: GOOD ]";
        }


        this.certificate = new CertificateDTO(certificate);;
        this.children = new ArrayList<>();
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public CertificateDTO getCertificate() {
        return certificate;
    }

    public void setCertificate(CertificateDTO certificate) {
        this.certificate = certificate;
    }

    public ArrayList<TreeItem> getChildren() {
        return children;
    }

    public void setChildren(ArrayList<TreeItem> children) {
        this.children = children;
    }
}
