package com.trevorism.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicOriginTest {

    @Test
    void testHostnameStripsPort() {
        assertEquals("localhost", new PublicOrigin("http", "localhost:5173").hostname());
        assertEquals("www.trevorism.com", new PublicOrigin("https", "www.trevorism.com").hostname());
    }

    @Test
    void testHostnameKeepsIpv6Literal() {
        assertEquals("[::1]", new PublicOrigin("http", "[::1]:8080").hostname());
        assertEquals("[::1]", new PublicOrigin("http", "[::1]").hostname());
        assertEquals("[2001:db8::1]", new PublicOrigin("https", "[2001:db8::1]:443").hostname());
    }

    @Test
    void testLoopbackDetection() {
        assertTrue(new PublicOrigin("http", "localhost:5173").isLoopback());
        assertTrue(new PublicOrigin("http", "127.0.0.1:8080").isLoopback());
        assertTrue(new PublicOrigin("http", "[::1]:8080").isLoopback());
        assertTrue(new PublicOrigin("http", "LOCALHOST").isLoopback());
        assertFalse(new PublicOrigin("https", "localhost.evil.net").isLoopback());
        assertFalse(new PublicOrigin("https", "www.trevorism.com").isLoopback());
    }

    @Test
    void testSecureCookiesRequiredUnlessHttpLoopback() {
        assertFalse(new PublicOrigin("http", "localhost:5173").requiresSecureCookies());
        assertFalse(new PublicOrigin("HTTP", "127.0.0.1:8080").requiresSecureCookies());
        assertTrue(new PublicOrigin("https", "localhost:8443").requiresSecureCookies());
        assertTrue(new PublicOrigin("http", "www.trevorism.com").requiresSecureCookies());
    }

    @Test
    void testOrigin() {
        assertEquals("http://localhost:5173", new PublicOrigin("http", "localhost:5173").origin());
    }
}
