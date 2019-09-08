package com.businesssystemssecurity.proj.web.dto.user;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class UserUpdateDTO {

    @Size(min = 3, max = 30)
    @NotNull
    private String firstName;

    @Size(min = 3, max = 30)
    @NotNull
    private String lastName;

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

}
