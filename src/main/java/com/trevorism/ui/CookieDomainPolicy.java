package com.trevorism.ui;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class CookieDomainPolicy {

    private final UiAuthConfiguration configuration;

    @Inject
    public CookieDomainPolicy(UiAuthConfiguration configuration) {
        this.configuration = configuration;
    }

    public String domainFor(String host) {
        if (host == null || host.isBlank()) {
            return null;
        }
        String hostname = new PublicOrigin("https", host).hostname().toLowerCase();
        for (String platformDomain : configuration.getPlatformDomains()) {
            if (platformDomain == null || platformDomain.isBlank()) {
                continue;
            }
            String normalized = platformDomain.toLowerCase().trim();
            if (hostname.equals(normalized) || hostname.endsWith("." + normalized)) {
                return normalized;
            }
        }
        return null;
    }
}
