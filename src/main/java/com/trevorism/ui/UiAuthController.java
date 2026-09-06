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

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Controller(UiAuthController.BASE_PATH)
public class UiAuthController {

    public static final String BASE_PATH = "/api/auth";
    public static final String CALLBACK_PATH = BASE_PATH + "/callback";

    private static final Logger log = LoggerFactory.getLogger(UiAuthController.class);
    private static final String DEFAULT_NEXT = "/";
    private static final String PROTOCOL_RELATIVE_PREFIX = "//";
    private static final String BACKSLASH_PREFIX = "/\\";
    private static final Pattern SAFE_NEXT = Pattern.compile("/[\\x21-\\x5B\\x5D-\\x7E]*");
    private static final int MAX_NEXT_LENGTH = 512;
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
                .cookie(cookieWriter.stateCookie(origin, encodeStateCookie(state, safeNext)));
    }

    @Get("/callback")
    public HttpResponse<?> callback(@Nullable @QueryValue("code") String code,
                                    @Nullable @QueryValue("state") String state,
                                    @Nullable @CookieValue(SessionCookieWriter.STATE_COOKIE) String stateCookie,
                                    HttpRequest<?> request) {
        PublicOrigin origin = originResolver.resolve(request);
        if (isBlank(code) || isBlank(state) || isBlank(stateCookie)) {
            return abandonCallback(origin, "missing handoff code or state");
        }
        String[] parts = stateCookie.split(":", 2);
        if (!constantTimeEquals(parts[0], state)) {
            return abandonCallback(origin, "state did not match the state cookie");
        }
        HandoffTokens tokens = authProviderClient.redeemCode(code, redirectUri(origin));
        if (tokens == null) {
            return abandonCallback(origin, "auth-provider refused the handoff code");
        }
        SessionClaims claims = claimsReader.read(tokens.getAccessToken());
        if (claims == null) {
            return abandonCallback(origin, "the handed off access token could not be read");
        }
        String next = decodeNextFromStateCookie(stateCookie);
        MutableHttpResponse<Object> response = found(next);
        applyCookies(response, cookieWriter.sessionCookies(origin, tokens.getAccessToken(), tokens.getRefreshToken(), claims));
        return response.cookie(cookieWriter.clearedStateCookie(origin));
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
            MutableHttpResponse<Object> cleared = HttpResponse.ok(unauthenticatedBody());
            if (claimsReader.isSigningKeyUsable()) {
                applyCookies(cleared, cookieWriter.clearedCookies(origin));
            }
            return cleared;
        }
        MutableHttpResponse<Object> response = HttpResponse.ok(authenticatedBody(refreshed));
        applyCookies(response, cookieWriter.accessTokenCookies(origin, accessToken));
        return response;
    }

    @Post(value = "/refresh", consumes = MediaType.ALL)
    public HttpResponse<?> refresh(@Nullable @CookieValue(SessionCookieWriter.REFRESH_COOKIE) String refreshToken,
                                   HttpRequest<?> request) {
        PublicOrigin origin = originResolver.resolve(request);
        if (isBlank(refreshToken)) {
            return clearedUnauthorized(origin);
        }
        String accessToken = authProviderClient.redeemRefreshToken(refreshToken);
        SessionClaims claims = claimsReader.read(accessToken);
        if (claims == null) {
            if (!claimsReader.isSigningKeyUsable()) {
                return HttpResponse.serverError();
            }
            return clearedUnauthorized(origin);
        }
        MutableHttpResponse<Object> response = HttpResponse.ok(authenticatedBody(claims));
        applyCookies(response, cookieWriter.accessTokenCookies(origin, accessToken));
        return response;
    }

    @Post(value = "/logout", consumes = MediaType.ALL)
    public HttpResponse<?> logout(HttpRequest<?> request) {
        PublicOrigin origin = originResolver.resolve(request);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("logoutUrl", configuration.getLoginUrl() + "/api/logout?redirect_uri=" + encode(origin.origin()));
        MutableHttpResponse<Object> response = HttpResponse.ok(body);
        applyCookies(response, cookieWriter.clearedCookies(origin));
        return response;
    }

    private HttpResponse<?> clearedUnauthorized(PublicOrigin origin) {
        MutableHttpResponse<Object> response = HttpResponse.unauthorized();
        applyCookies(response, cookieWriter.clearedCookies(origin));
        return response;
    }

    private HttpResponse<?> abandonCallback(PublicOrigin origin, String reason) {
        log.warn("Abandoning auth callback, {}", reason);
        return found(DEFAULT_NEXT + "?authError=1").cookie(cookieWriter.clearedStateCookie(origin));
    }

    private static void applyCookies(MutableHttpResponse<Object> response, List<Cookie> cookies) {
        cookies.forEach(response::cookie);
    }

    private static MutableHttpResponse<Object> found(String location) {
        return HttpResponse.status(HttpStatus.FOUND).header(HttpHeaders.LOCATION, location);
    }

    private String authorizeUri(PublicOrigin origin, String state) {
        StringBuilder builder = new StringBuilder(configuration.getLoginUrl())
                .append("/authorize?redirect_uri=").append(encode(redirectUri(origin)))
                .append("&state=").append(encode(state));
        String tenantGuid = configuration.getTenantGuid();
        if (tenantGuid != null && !tenantGuid.isBlank()) {
            builder.append("&tenant=").append(encode(tenantGuid));
        }
        return builder.toString();
    }

    private static String redirectUri(PublicOrigin origin) {
        return origin.origin() + CALLBACK_PATH;
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
        if (next == null || next.isBlank() || !next.startsWith(DEFAULT_NEXT)) {
            return DEFAULT_NEXT;
        }
        if (next.startsWith(PROTOCOL_RELATIVE_PREFIX) || next.startsWith(BACKSLASH_PREFIX)) {
            return DEFAULT_NEXT;
        }
        if (next.length() > MAX_NEXT_LENGTH || !SAFE_NEXT.matcher(next).matches()) {
            return DEFAULT_NEXT;
        }
        return next;
    }

    static String encodeStateCookie(String state, String next) {
        return state + ":" + URLEncoder.encode(next, StandardCharsets.UTF_8);
    }

    static String decodeNextFromStateCookie(String stateCookie) {
        int separator = stateCookie.indexOf(':');
        if (separator < 0 || separator == stateCookie.length() - 1) {
            return DEFAULT_NEXT;
        }
        try {
            return safeNext(URLDecoder.decode(stateCookie.substring(separator + 1), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            return DEFAULT_NEXT;
        }
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
