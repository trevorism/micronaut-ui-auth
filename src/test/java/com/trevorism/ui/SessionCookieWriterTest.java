package com.trevorism.ui;

import com.trevorism.secure.Roles;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.SameSite;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionCookieWriterTest {

    private static final PublicOrigin PLATFORM = new PublicOrigin("https", "certs.project.trevorism.com");
    private static final PublicOrigin APPSPOT = new PublicOrigin("https", "pr-10-dot-trevorism-auth.uk.r.appspot.com");
    private static final PublicOrigin LOCAL = new PublicOrigin("http", "localhost:5173");

    private static SessionCookieWriter writer() {
        UiAuthConfiguration configuration = new UiAuthConfiguration();
        configuration.setPlatformDomains(List.of("trevorism.com"));
        return new SessionCookieWriter(new CookieDomainPolicy(configuration));
    }

    private static SessionClaims claims(String role) {
        return new SessionClaims("tester", role, "CRUDE", null, Instant.now().plusSeconds(900));
    }

    private static Cookie find(Set<Cookie> cookies, String name, String domain) {
        Optional<Cookie> match = cookies.stream()
                .filter(cookie -> cookie.getName().equals(name))
                .filter(cookie -> java.util.Objects.equals(cookie.getDomain(), domain))
                .findFirst();
        return match.orElse(null);
    }

    @Test
    void testSessionCookieIsHttpOnlyAndScopedToPlatformDomain() {
        Set<Cookie> cookies = writer().sessionCookies(PLATFORM, "access", "refresh", claims(Roles.USER));

        Cookie session = find(cookies, SessionCookieWriter.SESSION_COOKIE, "trevorism.com");
        assertNotNull(session);
        assertEquals("access", session.getValue());
        assertTrue(session.isHttpOnly());
        assertTrue(session.isSecure());
        assertEquals("/", session.getPath());
        assertEquals(SessionCookieWriter.ACCESS_MAX_AGE_SECONDS, session.getMaxAge());
        assertEquals(Optional.of(SameSite.Lax), session.getSameSite());
    }

    @Test
    void testRefreshCookieUsesLongerLifetime() {
        Set<Cookie> cookies = writer().sessionCookies(PLATFORM, "access", "refresh", claims(Roles.USER));

        Cookie refresh = find(cookies, SessionCookieWriter.REFRESH_COOKIE, "trevorism.com");
        assertNotNull(refresh);
        assertTrue(refresh.isHttpOnly());
        assertEquals(SessionCookieWriter.REFRESH_MAX_AGE_SECONDS, refresh.getMaxAge());
    }

    @Test
    void testCompatibilityCookiesAreReadableByScripts() {
        Set<Cookie> cookies = writer().sessionCookies(PLATFORM, "access", "refresh", claims(Roles.TENANT_ADMIN));

        Cookie userName = find(cookies, SessionCookieWriter.USER_NAME_COOKIE, "trevorism.com");
        Cookie admin = find(cookies, SessionCookieWriter.ADMIN_COOKIE, "trevorism.com");
        assertNotNull(userName);
        assertNotNull(admin);
        assertFalse(userName.isHttpOnly());
        assertFalse(admin.isHttpOnly());
        assertEquals("tester", userName.getValue());
        assertEquals("true", admin.getValue());
    }

    @Test
    void testAdminCookieIsFalseForOrdinaryUser() {
        Set<Cookie> cookies = writer().sessionCookies(PLATFORM, "access", "refresh", claims(Roles.USER));

        assertEquals("false", find(cookies, SessionCookieWriter.ADMIN_COOKIE, "trevorism.com").getValue());
    }

    @Test
    void testNonPlatformHostGetsHostOnlyCookies() {
        Set<Cookie> cookies = writer().sessionCookies(APPSPOT, "access", "refresh", claims(Roles.USER));

        Cookie session = find(cookies, SessionCookieWriter.SESSION_COOKIE, null);
        assertNotNull(session);
        assertNull(session.getDomain());
        assertTrue(session.isSecure());
    }

    @Test
    void testLocalhostOverHttpDropsSecureFlag() {
        Set<Cookie> cookies = writer().sessionCookies(LOCAL, "access", "refresh", claims(Roles.USER));

        Cookie session = find(cookies, SessionCookieWriter.SESSION_COOKIE, null);
        assertNotNull(session);
        assertFalse(session.isSecure());
        assertTrue(session.isHttpOnly());
    }

    @Test
    void testRefreshCookieIsOmittedWhenAbsent() {
        Set<Cookie> cookies = writer().sessionCookies(PLATFORM, "access", null, claims(Roles.USER));

        assertNull(find(cookies, SessionCookieWriter.REFRESH_COOKIE, "trevorism.com"));
        assertNotNull(find(cookies, SessionCookieWriter.SESSION_COOKIE, "trevorism.com"));
    }

    @Test
    void testClearedCookiesCoverPlatformDomainAndHostOnly() {
        Set<Cookie> cookies = writer().clearedCookies(PLATFORM);

        assertEquals(8, cookies.size());
        for (String name : List.of(SessionCookieWriter.SESSION_COOKIE, SessionCookieWriter.REFRESH_COOKIE,
                SessionCookieWriter.USER_NAME_COOKIE, SessionCookieWriter.ADMIN_COOKIE)) {
            assertNotNull(find(cookies, name, "trevorism.com"), name + " on platform domain");
            assertNotNull(find(cookies, name, null), name + " host-only");
        }
        cookies.forEach(cookie -> assertEquals(0L, cookie.getMaxAge()));
    }

    @Test
    void testClearedCookiesOnNonPlatformHostAreHostOnly() {
        Set<Cookie> cookies = writer().clearedCookies(APPSPOT);

        assertEquals(4, cookies.size());
        cookies.forEach(cookie -> assertNull(cookie.getDomain()));
    }

    @Test
    void testStateCookieIsScopedToAuthPath() {
        Cookie state = writer().stateCookie(PLATFORM, "abc:/report");

        assertEquals(SessionCookieWriter.STATE_PATH, state.getPath());
        assertTrue(state.isHttpOnly());
        assertEquals(SessionCookieWriter.STATE_MAX_AGE_SECONDS, state.getMaxAge());
        assertEquals("abc:/report", state.getValue());
    }

    @Test
    void testClearedStateCookieExpiresImmediately() {
        Cookie state = writer().clearedStateCookie(PLATFORM);

        assertEquals(0L, state.getMaxAge());
        assertEquals(SessionCookieWriter.STATE_PATH, state.getPath());
    }
}
