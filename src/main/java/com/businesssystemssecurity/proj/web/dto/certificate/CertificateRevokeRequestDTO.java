package com.businesssystemssecurity.proj.web.dto.certificate;

public class CertificateRevokeRequestDTO {
    private String serialNumber;
    private String reason;

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
}
