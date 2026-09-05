package com.trevorism.ui;

import io.micronaut.http.HttpRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicOriginResolverTest {

    private final PublicOriginResolver resolver = new PublicOriginResolver();

    @Test
    void testForwardedHeadersWin() {
        HttpRequest<?> request = HttpRequest.GET("http://10.0.0.1:8080/api/auth/login")
                .header(PublicOriginResolver.FORWARDED_PROTO, "https")
                .header(PublicOriginResolver.FORWARDED_HOST, "certs.project.trevorism.com");

        PublicOrigin origin = resolver.resolve(request);

        assertEquals("https://certs.project.trevorism.com", origin.origin());
    }

    @Test
    void testForwardedHeaderListTakesFirstEntry() {
        HttpRequest<?> request = HttpRequest.GET("http://10.0.0.1:8080/api/auth/login")
                .header(PublicOriginResolver.FORWARDED_PROTO, "https, http")
                .header(PublicOriginResolver.FORWARDED_HOST, "app.trevorism.com, internal.lb");

        PublicOrigin origin = resolver.resolve(request);

        assertEquals("https://app.trevorism.com", origin.origin());
    }

    @Test
    void testFallsBackToHostHeader() {
        HttpRequest<?> request = HttpRequest.GET("http://ignored/api/auth/login")
                .header("Host", "localhost:5173");

        PublicOrigin origin = resolver.resolve(request);

        assertEquals("http://localhost:5173", origin.origin());
        assertTrue(origin.isLoopback());
        assertFalse(origin.requiresSecureCookies());
    }

    @Test
    void testLocalhostOverHttpsStillRequiresSecureCookies() {
        HttpRequest<?> request = HttpRequest.GET("https://localhost:8443/api/auth/login")
                .header("Host", "localhost:8443")
                .header(PublicOriginResolver.FORWARDED_PROTO, "https");

        assertTrue(resolver.resolve(request).requiresSecureCookies());
    }

    @Test
    void testEmptyForwardedHeaderEntryIsIgnored() {
        HttpRequest<?> request = HttpRequest.GET("http://ignored/api/auth/login")
                .header("Host", "www.trevorism.com")
                .header(PublicOriginResolver.FORWARDED_HOST, ",lb.internal");

        assertEquals("www.trevorism.com", resolver.resolve(request).host());
    }
}
