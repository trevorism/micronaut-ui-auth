package com.trevorism.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthProviderClientTest {

    private static AuthProviderClient client(StubHttpClient httpClient) {
        AuthProviderClient authProviderClient = new AuthProviderClient(new UiAuthConfiguration());
        authProviderClient.setHttpClient(httpClient);
        return authProviderClient;
    }

    @Test
    void testRedeemCodeReturnsTokens() {
        StubHttpClient httpClient = new StubHttpClient("{\"accessToken\":\"access.jwt\",\"refreshToken\":\"refresh.jwt\"}");

        HandoffTokens tokens = client(httpClient).redeemCode("1000.secret", "https://app.trevorism.com/api/auth/callback");

        assertNotNull(tokens);
        assertEquals("access.jwt", tokens.getAccessToken());
        assertEquals("refresh.jwt", tokens.getRefreshToken());
        assertEquals("https://auth.trevorism.com/token/handoff/redeem", httpClient.lastUrl);
        assertTrue(httpClient.lastBody.contains("1000.secret"));
        assertTrue(httpClient.lastBody.contains("https://app.trevorism.com/api/auth/callback"));
    }

    @Test
    void testRedeemCodeReturnsNullWhenAuthProviderRejects() {
        assertNull(client(StubHttpClient.failing(400)).redeemCode("1000.secret", "https://app.trevorism.com/api/auth/callback"));
    }

    @Test
    void testRedeemCodeReturnsNullOnHtmlErrorBody() {
        StubHttpClient httpClient = new StubHttpClient("<html><body>Bad Request</body></html>");

        assertNull(client(httpClient).redeemCode("1000.secret", "https://app.trevorism.com/api/auth/callback"));
    }

    @Test
    void testRedeemCodeReturnsNullWhenAccessTokenMissing() {
        assertNull(client(new StubHttpClient("{\"refreshToken\":\"refresh.jwt\"}"))
                .redeemCode("1000.secret", "https://app.trevorism.com/api/auth/callback"));
    }

    @Test
    void testRedeemRefreshTokenReturnsTrimmedAccessToken() {
        StubHttpClient httpClient = new StubHttpClient("  header.payload.signature \n");

        String accessToken = client(httpClient).redeemRefreshToken("refresh.jwt");

        assertEquals("header.payload.signature", accessToken);
        assertEquals("https://auth.trevorism.com/token/refresh/redeem", httpClient.lastUrl);
        assertTrue(httpClient.lastBody.contains("refresh.jwt"));
    }

    @Test
    void testRedeemRefreshTokenReturnsNullOnFailure() {
        assertNull(client(StubHttpClient.failing(400)).redeemRefreshToken("refresh.jwt"));
        assertNull(client(new StubHttpClient("<html>nope</html>")).redeemRefreshToken("refresh.jwt"));
        assertNull(client(new StubHttpClient("")).redeemRefreshToken("refresh.jwt"));
    }

    @Test
    void testConfiguredAuthUrlIsUsed() {
        UiAuthConfiguration configuration = new UiAuthConfiguration();
        configuration.setAuthUrl("https://pr-10-dot-trevorism-auth.uk.r.appspot.com/");
        AuthProviderClient authProviderClient = new AuthProviderClient(configuration);
        StubHttpClient httpClient = new StubHttpClient("token");
        authProviderClient.setHttpClient(httpClient);

        authProviderClient.redeemRefreshToken("refresh.jwt");

        assertEquals("https://pr-10-dot-trevorism-auth.uk.r.appspot.com/token/refresh/redeem", httpClient.lastUrl);
    }
}
