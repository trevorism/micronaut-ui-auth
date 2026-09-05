package com.trevorism.ui;

import com.trevorism.secure.Roles;

import java.time.Instant;

public record SessionClaims(String username, String role, String permissions, String tenant, Instant expiresAt) {

    public boolean isAdmin() {
        return Roles.ADMIN.equals(role) || Roles.TENANT_ADMIN.equals(role);
    }
}
