package com.trevorism.ui;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UiAuthConfigurationTest {

    @Test
    void testDefaults() {
        UiAuthConfiguration configuration = new UiAuthConfiguration();

        assertEquals("https://login.auth.trevorism.com", configuration.getLoginUrl());
        assertEquals("https://auth.trevorism.com", configuration.getAuthUrl());
        assertEquals(List.of("trevorism.com"), configuration.getPlatformDomains());
        assertEquals("/api/auth/callback", configuration.getCallbackPath());
        assertNull(configuration.getTenantGuid());
    }

    @Test
    void testTrailingSlashesAreStrippedFromUrls() {
        UiAuthConfiguration configuration = new UiAuthConfiguration();
        configuration.setLoginUrl("https://login.auth.trevorism.com/");
        configuration.setAuthUrl("https://auth.trevorism.com/");

        assertEquals("https://login.auth.trevorism.com", configuration.getLoginUrl());
        assertEquals("https://auth.trevorism.com", configuration.getAuthUrl());
    }

    @Test
    void testBlankUrlsAreLeftAlone() {
        UiAuthConfiguration configuration = new UiAuthConfiguration();
        configuration.setLoginUrl("");
        configuration.setAuthUrl(null);

        assertEquals("", configuration.getLoginUrl());
        assertNull(configuration.getAuthUrl());
    }

    @Test
    void testNullPlatformDomainsBecomeEmpty() {
        UiAuthConfiguration configuration = new UiAuthConfiguration();
        configuration.setPlatformDomains(null);

        assertTrue(configuration.getPlatformDomains().isEmpty());
    }

    @Test
    void testOverrides() {
        UiAuthConfiguration configuration = new UiAuthConfiguration();
        configuration.setPlatformDomains(List.of("memowand.com"));
        configuration.setTenantGuid("guid-1");
        configuration.setCallbackPath("/api/auth/cb");

        assertEquals(List.of("memowand.com"), configuration.getPlatformDomains());
        assertEquals("guid-1", configuration.getTenantGuid());
        assertEquals("/api/auth/cb", configuration.getCallbackPath());
    }
}
