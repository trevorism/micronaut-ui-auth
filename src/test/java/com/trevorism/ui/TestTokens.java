package com.trevorism.ui;

import com.trevorism.PropertiesProvider;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;

final class TestTokens {

    static final String SIGNING_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    static final String OTHER_SIGNING_KEY = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";

    private TestTokens() {
    }

    static PropertiesProvider propertiesProvider() {
        return property -> SIGNING_KEY;
    }

    static String token(String subject, String role, long secondsUntilExpiry) {
        return token(subject, role, "CRUDE", null, secondsUntilExpiry, SIGNING_KEY);
    }

    static String token(String subject, String role, String permissions, String tenant, long secondsUntilExpiry, String signingKey) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(signingKey));
        var builder = Jwts.builder()
                .subject(subject)
                .issuer("https://trevorism.com")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(secondsUntilExpiry)));
        if (role != null) {
            builder.claim("role", role);
        }
        if (permissions != null) {
            builder.claim("permissions", permissions);
        }
        if (tenant != null) {
            builder.claim("tenant", tenant);
        }
        return builder.signWith(key).compact();
    }
}
