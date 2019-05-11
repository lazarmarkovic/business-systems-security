package com.businesssystemssecurity.proj.security.web.dto;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class LoginDTO {

    @Email
    @Size(min = 5, max = 30)
    @NotNull
    private String email;

    @Size(min = 6, max = 30)
    @NotNull
    private String password;

    public LoginDTO() {}

    public LoginDTO(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return this.email;
    }
    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
}