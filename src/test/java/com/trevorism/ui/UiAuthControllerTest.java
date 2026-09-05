package com.trevorism.ui;

import com.trevorism.secure.Roles;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.cookie.Cookie;
import org.junit.jupiter.api.Test;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UiAuthControllerTest {

    private static final String CALLBACK = "https://certs.project.trevorism.com/api/auth/callback";

    private StubHttpClient httpClient;

    private UiAuthController controller(String authProviderResponse) {
        return controller(new StubHttpClient(authProviderResponse));
    }

    private UiAuthController controller(StubHttpClient stub) {
        this.httpClient = stub;
        UiAuthConfiguration configuration = new UiAuthConfiguration();
        configuration.setPlatformDomains(List.of("trevorism.com"));
        AuthProviderClient authProviderClient = new AuthProviderClient(configuration);
        authProviderClient.setHttpClient(stub);
        return new UiAuthController(configuration,
                new PublicOriginResolver(),
                new SessionCookieWriter(new CookieDomainPolicy(configuration)),
                new SessionClaimsReader(TestTokens.propertiesProvider()),
                authProviderClient);
    }

    private static HttpRequest<?> request(String path) {
        return HttpRequest.GET("https://certs.project.trevorism.com" + path)
                .header("Host", "certs.project.trevorism.com")
                .header(PublicOriginResolver.FORWARDED_PROTO, "https")
                .header(PublicOriginResolver.FORWARDED_HOST, "certs.project.trevorism.com");
    }

    private static String location(HttpResponse<?> response) {
        return response.getHeaders().get("Location");
    }

    private static Cookie cookie(HttpResponse<?> response, String name) {
        Optional<Cookie> found = response.getCookies().getAll().stream()
                .filter(candidate -> candidate.getName().equals(name))
                .findFirst();
        return found.orElse(null);
    }

    @Test
    void testLoginRedirectsToAuthorizeWithStateCookie() {
        HttpResponse<?> response = controller("{}").login("/report", request("/api/auth/login?next=/report"));

        assertEquals(HttpStatus.FOUND, response.status());
        String target = location(response);
        assertTrue(target.startsWith("https://login.auth.trevorism.com/authorize?"));
        assertTrue(target.contains("redirect_uri=" + java.net.URLEncoder.encode(CALLBACK, StandardCharsets.UTF_8)));

        Cookie state = cookie(response, SessionCookieWriter.STATE_COOKIE);
        assertNotNull(state);
        assertTrue(state.isHttpOnly());
        assertEquals(SessionCookieWriter.STATE_PATH, state.getPath());
        assertTrue(state.getValue().endsWith(":/report"));
        assertTrue(target.contains("state=" + state.getValue().split(":", 2)[0]));
    }

    @Test
    void testLoginIncludesTenantWhenConfigured() {
        UiAuthConfiguration configuration = new UiAuthConfiguration();
        configuration.setTenantGuid("tenant-guid-1");
        AuthProviderClient authProviderClient = new AuthProviderClient(configuration);
        authProviderClient.setHttpClient(new StubHttpClient("{}"));
        UiAuthController controller = new UiAuthController(configuration,
                new PublicOriginResolver(),
                new SessionCookieWriter(new CookieDomainPolicy(configuration)),
                new SessionClaimsReader(TestTokens.propertiesProvider()),
                authProviderClient);

        HttpResponse<?> response = controller.login(null, request("/api/auth/login"));

        assertTrue(location(response).contains("tenant=tenant-guid-1"));
    }

    @Test
    void testOpenRedirectAttemptsFallBackToRoot() {
        assertEquals("/", UiAuthController.safeNext("//evil.example.org"));
        assertEquals("/", UiAuthController.safeNext("/\\evil.example.org"));
        assertEquals("/", UiAuthController.safeNext("https://evil.example.org"));
        assertEquals("/", UiAuthController.safeNext("report"));
        assertEquals("/", UiAuthController.safeNext(null));
        assertEquals("/", UiAuthController.safeNext(""));
        assertEquals("/report?tab=1", UiAuthController.safeNext("/report?tab=1"));
    }

    @Test
    void testLoginRejectsOpenRedirectInStateCookie() {
        HttpResponse<?> response = controller("{}").login("//evil.example.org", request("/api/auth/login"));

        assertTrue(cookie(response, SessionCookieWriter.STATE_COOKIE).getValue().endsWith(":/"));
    }

    @Test
    void testCallbackSetsCookiesAndRedirectsToNext() {
        String accessToken = TestTokens.token("tester", Roles.USER, 900);
        UiAuthController controller = controller("{\"accessToken\":\"" + accessToken + "\",\"refreshToken\":\"refresh.jwt\"}");

        HttpResponse<?> response = controller.callback("1000.secret", "abc", "abc:/report", request("/api/auth/callback"));

        assertEquals(HttpStatus.FOUND, response.status());
        assertEquals("/report", location(response));
        assertEquals(accessToken, cookie(response, SessionCookieWriter.SESSION_COOKIE).getValue());
        assertEquals("refresh.jwt", cookie(response, SessionCookieWriter.REFRESH_COOKIE).getValue());
        assertEquals("tester", cookie(response, SessionCookieWriter.USER_NAME_COOKIE).getValue());
        assertTrue(httpClient.lastBody.contains(CALLBACK));
    }

    @Test
    void testCallbackRejectsStateMismatch() {
        String accessToken = TestTokens.token("tester", Roles.USER, 900);
        UiAuthController controller = controller("{\"accessToken\":\"" + accessToken + "\"}");

        HttpResponse<?> response = controller.callback("1000.secret", "abc", "different:/report", request("/api/auth/callback"));

        assertEquals(HttpStatus.BAD_REQUEST, response.status());
    }

    @Test
    void testCallbackRejectsMissingStateCookie() {
        HttpResponse<?> response = controller("{}").callback("1000.secret", "abc", null, request("/api/auth/callback"));

        assertEquals(HttpStatus.BAD_REQUEST, response.status());
    }

    @Test
    void testCallbackRejectsMissingCode() {
        HttpResponse<?> response = controller("{}").callback(null, "abc", "abc:/report", request("/api/auth/callback"));

        assertEquals(HttpStatus.BAD_REQUEST, response.status());
    }

    @Test
    void testCallbackRejectsFailedRedeem() {
        HttpResponse<?> response = controller(StubHttpClient.failing(400))
                .callback("1000.secret", "abc", "abc:/report", request("/api/auth/callback"));

        assertEquals(HttpStatus.BAD_REQUEST, response.status());
    }

    @Test
    void testCallbackRejectsUnreadableAccessToken() {
        HttpResponse<?> response = controller("{\"accessToken\":\"not.a.jwt\"}")
                .callback("1000.secret", "abc", "abc:/report", request("/api/auth/callback"));

        assertEquals(HttpStatus.BAD_REQUEST, response.status());
    }

    @Test
    void testCallbackSanitisesNextFromStateCookie() {
        String accessToken = TestTokens.token("tester", Roles.USER, 900);
        UiAuthController controller = controller("{\"accessToken\":\"" + accessToken + "\"}");

        HttpResponse<?> response = controller.callback("1000.secret", "abc", "abc://evil.example.org", request("/api/auth/callback"));

        assertEquals("/", location(response));
    }

    @Test
    void testSessionReportsAuthenticatedUser() {
        String accessToken = TestTokens.token("tester", Roles.ADMIN, 900);

        HttpResponse<?> response = controller("{}").session(accessToken, null, request("/api/auth/session"));

        assertEquals(HttpStatus.OK, response.status());
        Map<?, ?> body = (Map<?, ?>) response.body();
        assertEquals(true, body.get("authenticated"));
        assertEquals("tester", body.get("username"));
        assertEquals(Roles.ADMIN, body.get("role"));
        assertEquals(true, body.get("admin"));
        assertNotNull(body.get("expiresAt"));
    }

    @Test
    void testSessionWithoutCookiesIsUnauthenticated() {
        HttpResponse<?> response = controller("{}").session(null, null, request("/api/auth/session"));

        assertEquals(HttpStatus.OK, response.status());
        assertEquals(false, ((Map<?, ?>) response.body()).get("authenticated"));
    }

    @Test
    void testSessionRefreshesExpiredAccessTokenUsingRefreshCookie() {
        String expired = TestTokens.token("tester", Roles.USER, -300);
        String fresh = TestTokens.token("tester", Roles.USER, 900);

        HttpResponse<?> response = controller(fresh).session(expired, "refresh.jwt", request("/api/auth/session"));

        assertEquals(true, ((Map<?, ?>) response.body()).get("authenticated"));
        assertEquals(fresh, cookie(response, SessionCookieWriter.SESSION_COOKIE).getValue());
    }

    @Test
    void testSessionClearsCookiesWhenRefreshFails() {
        HttpResponse<?> response = controller(StubHttpClient.failing(401))
                .session(null, "refresh.jwt", request("/api/auth/session"));

        assertEquals(false, ((Map<?, ?>) response.body()).get("authenticated"));
        assertEquals(0L, cookie(response, SessionCookieWriter.SESSION_COOKIE).getMaxAge());
    }

    @Test
    void testRefreshIssuesNewSessionCookie() {
        String fresh = TestTokens.token("tester", Roles.USER, 900);

        HttpResponse<?> response = controller(fresh).refresh("refresh.jwt", request("/api/auth/refresh"));

        assertEquals(HttpStatus.OK, response.status());
        assertEquals(fresh, cookie(response, SessionCookieWriter.SESSION_COOKIE).getValue());
    }

    @Test
    void testRefreshWithoutCookieIsUnauthorized() {
        HttpResponse<?> response = controller("{}").refresh(null, request("/api/auth/refresh"));

        assertEquals(HttpStatus.UNAUTHORIZED, response.status());
        assertEquals(0L, cookie(response, SessionCookieWriter.SESSION_COOKIE).getMaxAge());
    }

    @Test
    void testRefreshFailureClearsCookies() {
        HttpResponse<?> response = controller(StubHttpClient.failing(400)).refresh("refresh.jwt", request("/api/auth/refresh"));

        assertEquals(HttpStatus.UNAUTHORIZED, response.status());
        assertEquals(0L, cookie(response, SessionCookieWriter.REFRESH_COOKIE).getMaxAge());
    }

    @Test
    void testLogoutClearsCookiesAndReturnsLogoutUrl() {
        HttpResponse<?> response = controller("{}").logout(request("/api/auth/logout"));

        assertEquals(HttpStatus.OK, response.status());
        String logoutUrl = (String) ((Map<?, ?>) response.body()).get("logoutUrl");
        assertTrue(logoutUrl.startsWith("https://login.auth.trevorism.com/api/logout?redirect_uri="));
        assertEquals("https://certs.project.trevorism.com",
                URLDecoder.decode(logoutUrl.substring(logoutUrl.indexOf("redirect_uri=") + 13), StandardCharsets.UTF_8));
        assertEquals(0L, cookie(response, SessionCookieWriter.SESSION_COOKIE).getMaxAge());
        assertFalse(response.getCookies().getAll().isEmpty());
    }
}
