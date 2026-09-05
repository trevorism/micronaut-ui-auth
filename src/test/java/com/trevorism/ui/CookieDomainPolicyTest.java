package com.trevorism.ui;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class CookieDomainPolicyTest {

    private static CookieDomainPolicy policy(String... platformDomains) {
        UiAuthConfiguration configuration = new UiAuthConfiguration();
        configuration.setPlatformDomains(List.of(platformDomains));
        return new CookieDomainPolicy(configuration);
    }

    @Test
    void testPlatformDomainAndSubdomains() {
        CookieDomainPolicy policy = policy("trevorism.com");
        assertEquals("trevorism.com", policy.domainFor("trevorism.com"));
        assertEquals("trevorism.com", policy.domainFor("www.trevorism.com"));
        assertEquals("trevorism.com", policy.domainFor("certs.project.trevorism.com"));
        assertEquals("trevorism.com", policy.domainFor("WWW.Trevorism.COM"));
    }

    @Test
    void testLookalikeDomainsAreHostOnly() {
        CookieDomainPolicy policy = policy("trevorism.com");
        assertNull(policy.domainFor("trevorism.com.evil.net"));
        assertNull(policy.domainFor("eviltrevorism.com"));
    }

    @Test
    void testAppspotAndLocalhostAreHostOnly() {
        CookieDomainPolicy policy = policy("trevorism.com");
        assertNull(policy.domainFor("pr-10-dot-trevorism-auth.uk.r.appspot.com"));
        assertNull(policy.domainFor("localhost:5173"));
        assertNull(policy.domainFor("127.0.0.1:8080"));
    }

    @Test
    void testPortIsStrippedBeforeMatching() {
        assertEquals("trevorism.com", policy("trevorism.com").domainFor("www.trevorism.com:8443"));
    }

    @Test
    void testAdditionalPlatformDomain() {
        CookieDomainPolicy policy = policy("trevorism.com", "memowand.com");
        assertEquals("memowand.com", policy.domainFor("app.memowand.com"));
        assertEquals("trevorism.com", policy.domainFor("www.trevorism.com"));
    }

    @Test
    void testEmptyAndNullInputs() {
        CookieDomainPolicy policy = policy("trevorism.com");
        assertNull(policy.domainFor(null));
        assertNull(policy.domainFor(""));
        assertNull(policy("").domainFor("www.trevorism.com"));
    }
}
