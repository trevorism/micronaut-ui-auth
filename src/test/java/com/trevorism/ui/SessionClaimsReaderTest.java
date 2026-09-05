package com.trevorism.ui;

import com.trevorism.secure.Roles;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionClaimsReaderTest {

    private final SessionClaimsReader reader = new SessionClaimsReader(TestTokens.propertiesProvider());

    @Test
    void testReadsClaimsFromValidToken() {
        String token = TestTokens.token("tester", Roles.USER, "RE", "tenant-a", 900, TestTokens.SIGNING_KEY);

        SessionClaims claims = reader.read(token);

        assertNotNull(claims);
        assertEquals("tester", claims.username());
        assertEquals(Roles.USER, claims.role());
        assertEquals("RE", claims.permissions());
        assertEquals("tenant-a", claims.tenant());
        assertNotNull(claims.expiresAt());
        assertFalse(claims.isAdmin());
    }

    @Test
    void testAdminRolesFlagAdmin() {
        assertTrue(reader.read(TestTokens.token("boss", Roles.ADMIN, 900)).isAdmin());
        assertTrue(reader.read(TestTokens.token("boss", Roles.TENANT_ADMIN, 900)).isAdmin());
        assertFalse(reader.read(TestTokens.token("boss", Roles.SYSTEM, 900)).isAdmin());
    }

    @Test
    void testExpiredTokenIsRejectedBeyondClockSkew() {
        assertNull(reader.read(TestTokens.token("tester", Roles.USER, -300)));
    }

    @Test
    void testTokenSignedWithAnotherKeyIsRejected() {
        String token = TestTokens.token("tester", Roles.USER, "RE", null, 900, TestTokens.OTHER_SIGNING_KEY);

        assertNull(reader.read(token));
    }

    @Test
    void testGarbageIsRejected() {
        assertNull(reader.read(null));
        assertNull(reader.read(""));
        assertNull(reader.read("   "));
        assertNull(reader.read("not.a.jwt"));
    }

    @Test
    void testMissingSigningKeyIsRejectedWithoutThrowing() {
        SessionClaimsReader broken = new SessionClaimsReader(property -> null);

        assertNull(broken.read(TestTokens.token("tester", Roles.USER, 900)));
    }

    @Test
    void testUnreadableSigningKeyPropertyIsRejectedWithoutThrowing() {
        SessionClaimsReader broken = new SessionClaimsReader(property -> {
            throw new IllegalStateException("secrets.properties is not on the classpath");
        });

        assertNull(broken.read(TestTokens.token("tester", Roles.USER, 900)));
    }

    @Test
    void testUnusableSigningKeyValueIsRejectedWithoutThrowing() {
        SessionClaimsReader broken = new SessionClaimsReader(property -> "tooshort");

        assertNull(broken.read(TestTokens.token("tester", Roles.USER, 900)));
    }

    @Test
    void testTokenFromAnotherIssuerIsRejected() {
        String token = TestTokens.tokenWithIssuer("tester", Roles.USER, "RE", null, 900,
                TestTokens.SIGNING_KEY, "https://evil.example.org");

        assertNull(reader.read(token));
    }

    @Test
    void testProductionShapedTokenIsReadable() {
        SessionClaimsReader hs512Reader = new SessionClaimsReader(property -> TestTokens.HS512_SIGNING_KEY);

        SessionClaims claims = hs512Reader.read(TestTokens.productionShapedToken("agent", Roles.USER));

        assertNotNull(claims);
        assertEquals("agent", claims.username());
        assertEquals(Roles.USER, claims.role());
        assertEquals("CRE", claims.permissions());
        assertNull(claims.tenant());
        assertNotNull(claims.expiresAt());
    }
}
