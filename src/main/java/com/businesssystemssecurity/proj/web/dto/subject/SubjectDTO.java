package com.businesssystemssecurity.proj.web.dto.subject;

public class SubjectDTO {
    private String commonName = "";
    private String organizationUnit = "";
    private String organization = "";
    private String locality = "";
    private String state = "";
    private String country = "";

    public SubjectDTO() {}

    public SubjectDTO(String commonName, String organizationUnit, String organization, String locality, String state, String country) {
        this.commonName = commonName;
        this.organizationUnit = organizationUnit;
        this.organization = organization;
        this.locality = locality;
        this.state = state;
        this.country = country;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getOrganizationUnit() {
        return organizationUnit;
    }

    public void setOrganizationUnit(String organizationUnit) {
        this.organizationUnit = organizationUnit;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }
}
