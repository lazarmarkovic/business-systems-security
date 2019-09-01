package com.businesssystemssecurity.proj.web.dto.subject;

public class SubjectDTO {
    private String commonName = "";
    private String organizationUnit = "";
    private String organization = "";
    private String country = "";

    public SubjectDTO() {}

    public SubjectDTO(String commonName, String organizationUnit, String organization, String country) {
        this.commonName = commonName;
        this.organizationUnit = organizationUnit;
        this.organization = organization;
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

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }
}
