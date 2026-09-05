package com.trevorism.ui;

import io.micronaut.http.HttpRequest;
import jakarta.inject.Singleton;

@Singleton
public class PublicOriginResolver {

    static final String FORWARDED_PROTO = "X-Forwarded-Proto";
    static final String FORWARDED_HOST = "X-Forwarded-Host";
    private static final String HTTPS = "https";

    public PublicOrigin resolve(HttpRequest<?> request) {
        return new PublicOrigin(resolveScheme(request), resolveHost(request));
    }

    private static String resolveScheme(HttpRequest<?> request) {
        String forwarded = firstValue(request.getHeaders().get(FORWARDED_PROTO));
        if (forwarded != null) {
            return forwarded.toLowerCase();
        }
        String scheme = request.getUri().getScheme();
        return scheme == null ? HTTPS : scheme.toLowerCase();
    }

    private static String resolveHost(HttpRequest<?> request) {
        String forwarded = firstValue(request.getHeaders().get(FORWARDED_HOST));
        if (forwarded != null) {
            return forwarded;
        }
        String host = firstValue(request.getHeaders().get(io.micronaut.http.HttpHeaders.HOST));
        if (host != null) {
            return host;
        }
        return request.getUri().getAuthority();
    }

    private static String firstValue(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return null;
        }
        int comma = headerValue.indexOf(',');
        String first = comma < 0 ? headerValue : headerValue.substring(0, comma);
        first = first.trim();
        return first.isEmpty() ? null : first;
    }
}
