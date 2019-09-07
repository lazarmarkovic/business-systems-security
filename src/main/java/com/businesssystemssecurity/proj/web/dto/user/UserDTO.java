package com.businesssystemssecurity.proj.web.dto.user;

import com.businesssystemssecurity.proj.domain.User;
import com.businesssystemssecurity.proj.web.dto.authority.AuthorityDTO;
import com.businesssystemssecurity.proj.web.dto.permission.PermissionDTO;

import java.util.Set;
import java.util.stream.Collectors;

public class UserDTO {
    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private Set<AuthorityDTO> userAuthorities;
    private Set<PermissionDTO> userPermissions;

    public UserDTO(Long id, String email, String firstName, String lastName) {
        this.id = id;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    public UserDTO(User u) {
        this.id = u.getId();
        this.email = u.getEmail();
        this.firstName = u.getFirstName();
        this.lastName = u.getLastName();

        this.userAuthorities = u.getUserAuthorities().stream().map(ua ->
                new AuthorityDTO(ua.getAuthority())
        ).collect(Collectors.toSet());

        this.userPermissions = u.getUserPermissions().stream().map(ua ->
                new PermissionDTO(ua.getPermission())
        ).collect(Collectors.toSet());
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

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

    public Set<AuthorityDTO> getUserAuthorities() {
        return userAuthorities;
    }

    public void setUserAuthorities(Set<AuthorityDTO> userAuthorities) {
        this.userAuthorities = userAuthorities;
    }

    public Set<PermissionDTO> getUserPermissions() {
        return userPermissions;
    }

    public void setUserPermissions(Set<PermissionDTO> userPermissions) {
        this.userPermissions = userPermissions;
    }
}
