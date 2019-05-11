package com.businesssystemssecurity.proj.web.dto.user;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class UserPasswordDTO {

    @Size(min = 5, max = 20)
    @NotNull
    private String oldPassword;

    @Size(min = 5, max = 20)
    @NotNull
    private String newPassword;

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getOldPassword() {
        return oldPassword;
    }

    public void setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
    }
}
