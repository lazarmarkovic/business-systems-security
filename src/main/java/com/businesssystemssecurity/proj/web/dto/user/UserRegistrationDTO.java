package com.businesssystemssecurity.proj.web.dto.user;

import javax.validation.constraints.Email;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class UserRegistrationDTO {

    @Size(min = 3, max = 30)
    @NotNull
    private String firstName;

    @Size(min = 3, max = 30)
    @NotNull
    private String lastName;

    @Email
    @Size(min = 5, max = 30)
    @NotNull
    private String email;

    @Size(min = 5, max = 30)
    @NotNull
    private String password;


    private Long authorityId;

    @NotNull
    private long[] permissions;

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
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

    public Long getAuthorityId() {
        return authorityId;
    }

    public void setAuthorityId(Long authorityId) {
        this.authorityId = authorityId;
    }

    public long[] getPermissions() {
        return permissions;
    }

    public void setPermissions(long[] permissions) {
        this.permissions = permissions;
    }
}
