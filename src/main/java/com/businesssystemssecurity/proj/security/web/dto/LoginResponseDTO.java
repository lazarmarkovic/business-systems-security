package com.businesssystemssecurity.proj.security.web.dto;

public class LoginResponseDTO {
    private Long userId;
    private String token;


    public LoginResponseDTO() {}

    public LoginResponseDTO(Long id, String token) {
        this();
        this.userId = id;
        this.token = token;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getToken() {
        return token;
    }
    public void setToken(String token) {
        this.token = token;
    }
}
