package com.trevorism.ui;

import com.google.gson.Gson;
import com.trevorism.http.HttpClient;
import com.trevorism.http.JsonHttpClient;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;

@Singleton
public class AuthProviderClient {

    private static final Logger log = LoggerFactory.getLogger(AuthProviderClient.class);

    private final UiAuthConfiguration configuration;
    private final Gson gson = new Gson();
    private HttpClient httpClient = new JsonHttpClient();

    @Inject
    public AuthProviderClient(UiAuthConfiguration configuration) {
        this.configuration = configuration;
    }

    public HandoffTokens redeemCode(String code, String redirectUri) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("code", code);
        body.put("redirectUri", redirectUri);
        try {
            String response = httpClient.post(configuration.getAuthUrl() + "/token/handoff/redeem", gson.toJson(body));
            if (isFailureBody(response)) {
                return null;
            }
            HandoffTokens tokens = gson.fromJson(response, HandoffTokens.class);
            return tokens == null || tokens.getAccessToken() == null ? null : tokens;
        } catch (Exception e) {
            log.warn("Unable to redeem handoff code: {}", e.getMessage());
            return null;
        }
    }

    public String redeemRefreshToken(String refreshToken) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("refreshToken", refreshToken);
        try {
            String response = httpClient.post(configuration.getAuthUrl() + "/token/refresh/redeem", gson.toJson(body));
            return isFailureBody(response) ? null : response.trim();
        } catch (Exception e) {
            log.debug("Unable to redeem refresh token: {}", e.getMessage());
            return null;
        }
    }

    private static boolean isFailureBody(String response) {
        return response == null || response.isBlank() || response.trim().startsWith("<");
    }

    void setHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }
}
