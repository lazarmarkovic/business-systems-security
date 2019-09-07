package com.businesssystemssecurity.proj.web.dto.permission;

import com.businesssystemssecurity.proj.domain.Permission;

public class PermissionDTO {
    private long id;
    private String name;

    public PermissionDTO() {}

    public PermissionDTO(int id, String name) {
        this.id = id;
        this.name = name;
    }

    public PermissionDTO(Permission p) {
        this.id = p.getId();
        this.name = p.getName();
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
}
