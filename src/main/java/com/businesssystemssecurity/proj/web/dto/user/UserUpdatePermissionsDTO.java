package com.businesssystemssecurity.proj.web.dto.user;

import java.util.Arrays;

public class UserUpdatePermissionsDTO {
    private long[] permissions;
    private boolean suspended;

    public long[] getPermissions() {
        return permissions;
    }

    public void setPermissions(long[] permissions) {
        this.permissions = permissions;
    }

    public boolean isSuspended() {
        return suspended;
    }

    public void setSuspended(boolean suspended) {
        this.suspended = suspended;
    }

    @Override
    public String toString() {
        return "UserUpdatePermissionsDTO{" +
                "permissions=" + Arrays.toString(permissions) +
                ", suspended=" + suspended +
                '}';
    }
}
