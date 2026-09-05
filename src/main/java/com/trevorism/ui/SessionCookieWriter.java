package com.trevorism.ui;

import com.trevorism.micronaut.SecurityConstants;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.SameSite;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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
    public static final String ROOT_PATH = "/";
    public static final String STATE_PATH = "/api/auth";

    private final CookieDomainPolicy cookieDomainPolicy;

    @Inject
    public SessionCookieWriter(CookieDomainPolicy cookieDomainPolicy) {
        this.cookieDomainPolicy = cookieDomainPolicy;
    }

    public List<Cookie> sessionCookies(PublicOrigin origin, String accessToken, String refreshToken, SessionClaims claims) {
        List<Cookie> cookies = new ArrayList<>(accessTokenCookies(origin, accessToken));
        if (refreshToken != null && !refreshToken.isBlank()) {
            cookies.add(build(origin, REFRESH_COOKIE, refreshToken, REFRESH_MAX_AGE_SECONDS, true, ROOT_PATH));
        }
        cookies.addAll(compatibilityCookies(origin, claims));
        return cookies;
    }

    public List<Cookie> accessTokenCookies(PublicOrigin origin, String accessToken) {
        return List.of(build(origin, SESSION_COOKIE, accessToken, ACCESS_MAX_AGE_SECONDS, true, ROOT_PATH));
    }

    public List<Cookie> compatibilityCookies(PublicOrigin origin, SessionClaims claims) {
        if (claims == null) {
            return List.of();
        }
        String username = claims.username() == null ? "" : claims.username();
        return List.of(
                build(origin, USER_NAME_COOKIE, username, REFRESH_MAX_AGE_SECONDS, false, ROOT_PATH),
                build(origin, ADMIN_COOKIE, Boolean.toString(claims.isAdmin()), REFRESH_MAX_AGE_SECONDS, false, ROOT_PATH));
    }

    public List<Cookie> clearedCookies(PublicOrigin origin) {
        List<Cookie> cookies = new ArrayList<>();
        for (String domain : clearingDomains(origin)) {
            cookies.add(cleared(origin, SESSION_COOKIE, true, ROOT_PATH, domain));
            cookies.add(cleared(origin, REFRESH_COOKIE, true, ROOT_PATH, domain));
            cookies.add(cleared(origin, USER_NAME_COOKIE, false, ROOT_PATH, domain));
            cookies.add(cleared(origin, ADMIN_COOKIE, false, ROOT_PATH, domain));
        }
        cookies.add(clearedStateCookie(origin));
        return cookies;
    }

    public Cookie stateCookie(PublicOrigin origin, String value) {
        return hostOnly(origin, STATE_COOKIE, value, STATE_MAX_AGE_SECONDS, STATE_PATH);
    }

    public Cookie clearedStateCookie(PublicOrigin origin) {
        return cleared(origin, STATE_COOKIE, true, STATE_PATH, null);
    }

    private Cookie build(PublicOrigin origin, String name, String value, long maxAge, boolean httpOnly, String path) {
        return decorate(Cookie.of(name, value), origin, maxAge, httpOnly, path, cookieDomainPolicy.domainFor(origin.host()));
    }

    private static Cookie hostOnly(PublicOrigin origin, String name, String value, long maxAge, String path) {
        return decorate(Cookie.of(name, value), origin, maxAge, true, path, null);
    }

    private static Cookie cleared(PublicOrigin origin, String name, boolean httpOnly, String path, String domain) {
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

    private List<String> clearingDomains(PublicOrigin origin) {
        String platformDomain = cookieDomainPolicy.domainFor(origin.host());
        if (platformDomain == null) {
            return Collections.singletonList(null);
        }
        return Arrays.asList(platformDomain, null);
    }
}
