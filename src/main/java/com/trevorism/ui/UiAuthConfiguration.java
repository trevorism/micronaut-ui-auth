package com.trevorism.ui;

import io.micronaut.context.annotation.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties("trevorism.ui-auth")
public class UiAuthConfiguration {

    private String loginUrl = "https://login.auth.trevorism.com";
    private String authUrl = "https://auth.trevorism.com";
    private List<String> platformDomains = List.of("trevorism.com");
    private String tenantGuid;
    private String callbackPath = "/api/auth/callback";

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = stripTrailingSlash(loginUrl);
    }

    public String getAuthUrl() {
        return authUrl;
    }

    public void setAuthUrl(String authUrl) {
        this.authUrl = stripTrailingSlash(authUrl);
    }

    public List<String> getPlatformDomains() {
        return platformDomains;
    }

    public void setPlatformDomains(List<String> platformDomains) {
        this.platformDomains = platformDomains == null ? List.of() : List.copyOf(platformDomains);
    }

    public String getTenantGuid() {
        return tenantGuid;
    }

    public void setTenantGuid(String tenantGuid) {
        this.tenantGuid = tenantGuid;
    }

    public String getCallbackPath() {
        return callbackPath;
    }

    public void setCallbackPath(String callbackPath) {
        this.callbackPath = callbackPath;
    }

    private static String stripTrailingSlash(String url) {
        if (url == null || url.isBlank()) {
            return url;
        }
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
