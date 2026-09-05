package com.trevorism.ui;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.CookieValue;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.QueryValue;
import io.micronaut.http.cookie.Cookie;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@Controller("/api/auth")
public class UiAuthController {

    private static final Logger log = LoggerFactory.getLogger(UiAuthController.class);
    private static final String DEFAULT_NEXT = "/";
    private static final String PROTOCOL_RELATIVE_PREFIX = "//";
    private static final String BACKSLASH_PREFIX = "/\\";
    private static final int STATE_BYTES = 32;

    private final UiAuthConfiguration configuration;
    private final PublicOriginResolver originResolver;
    private final SessionCookieWriter cookieWriter;
    private final SessionClaimsReader claimsReader;
    private final AuthProviderClient authProviderClient;
    private final SecureRandom secureRandom = new SecureRandom();

    @Inject
    public UiAuthController(UiAuthConfiguration configuration,
                            PublicOriginResolver originResolver,
                            SessionCookieWriter cookieWriter,
                            SessionClaimsReader claimsReader,
                            AuthProviderClient authProviderClient) {
        this.configuration = configuration;
        this.originResolver = originResolver;
        this.cookieWriter = cookieWriter;
        this.claimsReader = claimsReader;
        this.authProviderClient = authProviderClient;
    }

    @Get("/login")
    public HttpResponse<?> login(@Nullable @QueryValue("next") String next, HttpRequest<?> request) {
        PublicOrigin origin = originResolver.resolve(request);
        String state = generateState();
        String safeNext = safeNext(next);
        return found(authorizeUri(origin, state))
                .cookie(cookieWriter.stateCookie(origin, state + ":" + safeNext));
    }

    @Get("/callback")
    public HttpResponse<?> callback(@Nullable @QueryValue("code") String code,
                                    @Nullable @QueryValue("state") String state,
                                    @Nullable @CookieValue(SessionCookieWriter.STATE_COOKIE) String stateCookie,
                                    HttpRequest<?> request) {
        PublicOrigin origin = originResolver.resolve(request);
        if (isBlank(code) || isBlank(state) || isBlank(stateCookie)) {
            return badCallback(origin, "Missing handoff code or state");
        }
        String[] parts = stateCookie.split(":", 2);
        if (!constantTimeEquals(parts[0], state)) {
            return badCallback(origin, "State mismatch");
        }
        HandoffTokens tokens = authProviderClient.redeemCode(code, redirectUri(origin));
        if (tokens == null) {
            return badCallback(origin, "Unable to redeem handoff code");
        }
        SessionClaims claims = claimsReader.read(tokens.getAccessToken());
        if (claims == null) {
            return badCallback(origin, "Handoff returned an unreadable session");
        }
        Set<Cookie> cookies = new LinkedHashSet<>(
                cookieWriter.sessionCookies(origin, tokens.getAccessToken(), tokens.getRefreshToken(), claims));
        cookies.add(cookieWriter.clearedStateCookie(origin));
        String next = parts.length > 1 ? safeNext(parts[1]) : DEFAULT_NEXT;
        return found(URI.create(next)).cookies(cookies);
    }

    @Get("/session")
    public HttpResponse<?> session(@Nullable @CookieValue(SessionCookieWriter.SESSION_COOKIE) String sessionToken,
                                   @Nullable @CookieValue(SessionCookieWriter.REFRESH_COOKIE) String refreshToken,
                                   HttpRequest<?> request) {
        SessionClaims claims = claimsReader.read(sessionToken);
        if (claims != null) {
            return HttpResponse.ok(authenticatedBody(claims));
        }
        if (isBlank(refreshToken)) {
            return HttpResponse.ok(unauthenticatedBody());
        }
        PublicOrigin origin = originResolver.resolve(request);
        String accessToken = authProviderClient.redeemRefreshToken(refreshToken);
        SessionClaims refreshed = claimsReader.read(accessToken);
        if (refreshed == null) {
            return HttpResponse.ok(unauthenticatedBody()).cookies(cookieWriter.clearedCookies(origin));
        }
        return HttpResponse.ok(authenticatedBody(refreshed))
                .cookies(cookieWriter.sessionCookies(origin, accessToken, null, refreshed));
    }

    @Post("/refresh")
    public HttpResponse<?> refresh(@Nullable @CookieValue(SessionCookieWriter.REFRESH_COOKIE) String refreshToken,
                                   HttpRequest<?> request) {
        PublicOrigin origin = originResolver.resolve(request);
        if (isBlank(refreshToken)) {
            return HttpResponse.unauthorized().cookies(cookieWriter.clearedCookies(origin));
        }
        String accessToken = authProviderClient.redeemRefreshToken(refreshToken);
        SessionClaims claims = claimsReader.read(accessToken);
        if (claims == null) {
            return HttpResponse.unauthorized().cookies(cookieWriter.clearedCookies(origin));
        }
        return HttpResponse.ok(authenticatedBody(claims))
                .cookies(cookieWriter.sessionCookies(origin, accessToken, null, claims));
    }

    @Post("/logout")
    public HttpResponse<?> logout(HttpRequest<?> request) {
        PublicOrigin origin = originResolver.resolve(request);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("logoutUrl", configuration.getLoginUrl() + "/api/logout?redirect_uri=" + encode(origin.origin()));
        return HttpResponse.ok(body).cookies(cookieWriter.clearedCookies(origin));
    }

    private static MutableHttpResponse<Object> found(URI location) {
        return HttpResponse.status(HttpStatus.FOUND).header(HttpHeaders.LOCATION, location.toString());
    }

    private URI authorizeUri(PublicOrigin origin, String state) {
        StringBuilder builder = new StringBuilder(configuration.getLoginUrl())
                .append("/authorize?redirect_uri=").append(encode(redirectUri(origin)))
                .append("&state=").append(encode(state));
        String tenantGuid = configuration.getTenantGuid();
        if (tenantGuid != null && !tenantGuid.isBlank()) {
            builder.append("&tenant=").append(encode(tenantGuid));
        }
        return URI.create(builder.toString());
    }

    private String redirectUri(PublicOrigin origin) {
        return origin.origin() + configuration.getCallbackPath();
    }

    private HttpResponse<?> badCallback(PublicOrigin origin, String reason) {
        log.warn("Rejected auth callback: {}", reason);
        Set<Cookie> cookies = new LinkedHashSet<>(cookieWriter.clearedCookies(origin));
        cookies.add(cookieWriter.clearedStateCookie(origin));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", reason);
        return HttpResponse.badRequest(body).contentType(MediaType.APPLICATION_JSON).cookies(cookies);
    }

    private static Map<String, Object> authenticatedBody(SessionClaims claims) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("authenticated", true);
        body.put("username", claims.username());
        body.put("role", claims.role());
        body.put("permissions", claims.permissions());
        body.put("tenant", claims.tenant());
        body.put("admin", claims.isAdmin());
        body.put("expiresAt", claims.expiresAt() == null ? null : claims.expiresAt().toString());
        return body;
    }

    private static Map<String, Object> unauthenticatedBody() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("authenticated", false);
        return body;
    }

    static String safeNext(String next) {
        if (next == null || next.isBlank() || !next.startsWith("/")) {
            return DEFAULT_NEXT;
        }
        if (next.startsWith(PROTOCOL_RELATIVE_PREFIX) || next.startsWith(BACKSLASH_PREFIX)) {
            return DEFAULT_NEXT;
        }
        return next;
    }

    private String generateState() {
        byte[] bytes = new byte[STATE_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
