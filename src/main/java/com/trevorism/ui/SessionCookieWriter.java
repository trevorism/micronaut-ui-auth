package com.trevorism.ui;

import com.trevorism.micronaut.SecurityConstants;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.SameSite;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.util.LinkedHashSet;
import java.util.Set;

@Singleton
public class SessionCookieWriter {

    public static final String SESSION_COOKIE = SecurityConstants.Http.SESSION_COOKIE;
    public static final String REFRESH_COOKIE = "refresh_token";
    public static final String USER_NAME_COOKIE = "user_name";
    public static final String ADMIN_COOKIE = "admin";
    public static final String STATE_COOKIE = "ui_auth_state";

    public static final long ACCESS_MAX_AGE_SECONDS = 900L;
    public static final long REFRESH_MAX_AGE_SECONDS = 86400L;
    public static final long STATE_MAX_AGE_SECONDS = 600L;
    public static final String STATE_PATH = "/api/auth";

    private final CookieDomainPolicy cookieDomainPolicy;

    @Inject
    public SessionCookieWriter(CookieDomainPolicy cookieDomainPolicy) {
        this.cookieDomainPolicy = cookieDomainPolicy;
    }

    public Set<Cookie> sessionCookies(PublicOrigin origin, String accessToken, String refreshToken, SessionClaims claims) {
        Set<Cookie> cookies = new LinkedHashSet<>();
        cookies.add(build(origin, SESSION_COOKIE, accessToken, ACCESS_MAX_AGE_SECONDS, true, "/"));
        if (refreshToken != null && !refreshToken.isBlank()) {
            cookies.add(build(origin, REFRESH_COOKIE, refreshToken, REFRESH_MAX_AGE_SECONDS, true, "/"));
        }
        cookies.addAll(compatibilityCookies(origin, claims));
        return cookies;
    }

    public Set<Cookie> compatibilityCookies(PublicOrigin origin, SessionClaims claims) {
        Set<Cookie> cookies = new LinkedHashSet<>();
        if (claims == null) {
            return cookies;
        }
        String username = claims.username() == null ? "" : claims.username();
        cookies.add(build(origin, USER_NAME_COOKIE, username, REFRESH_MAX_AGE_SECONDS, false, "/"));
        cookies.add(build(origin, ADMIN_COOKIE, Boolean.toString(claims.isAdmin()), REFRESH_MAX_AGE_SECONDS, false, "/"));
        return cookies;
    }

    public Set<Cookie> clearedCookies(PublicOrigin origin) {
        Set<Cookie> cookies = new LinkedHashSet<>();
        for (String domain : clearingDomains(origin)) {
            cookies.add(cleared(origin, SESSION_COOKIE, true, "/", domain));
            cookies.add(cleared(origin, REFRESH_COOKIE, true, "/", domain));
            cookies.add(cleared(origin, USER_NAME_COOKIE, false, "/", domain));
            cookies.add(cleared(origin, ADMIN_COOKIE, false, "/", domain));
        }
        return cookies;
    }

    public Cookie stateCookie(PublicOrigin origin, String value) {
        return build(origin, STATE_COOKIE, value, STATE_MAX_AGE_SECONDS, true, STATE_PATH);
    }

    public Cookie clearedStateCookie(PublicOrigin origin) {
        return cleared(origin, STATE_COOKIE, true, STATE_PATH, cookieDomainPolicy.domainFor(origin.host()));
    }

    private Cookie build(PublicOrigin origin, String name, String value, long maxAge, boolean httpOnly, String path) {
        return decorate(Cookie.of(name, value), origin, maxAge, httpOnly, path, cookieDomainPolicy.domainFor(origin.host()));
    }

    private Cookie cleared(PublicOrigin origin, String name, boolean httpOnly, String path, String domain) {
        return decorate(Cookie.of(name, ""), origin, 0L, httpOnly, path, domain);
    }

    private static Cookie decorate(Cookie cookie, PublicOrigin origin, long maxAge, boolean httpOnly, String path, String domain) {
        cookie.path(path)
                .maxAge(maxAge)
                .httpOnly(httpOnly)
                .secure(origin.requiresSecureCookies())
                .sameSite(SameSite.Lax);
        if (domain != null) {
            cookie.domain(domain);
        }
        return cookie;
    }

    private java.util.List<String> clearingDomains(PublicOrigin origin) {
        String platformDomain = cookieDomainPolicy.domainFor(origin.host());
        if (platformDomain == null) {
            return java.util.Collections.singletonList(null);
        }
        return java.util.Arrays.asList(platformDomain, null);
    }
}
