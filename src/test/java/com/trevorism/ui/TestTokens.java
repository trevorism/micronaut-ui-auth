package com.trevorism.ui;

import com.trevorism.PropertiesProvider;
import com.trevorism.micronaut.SecurityConstants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

final class TestTokens {

    static final String SIGNING_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    static final String OTHER_SIGNING_KEY = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";
    static final String HS512_SIGNING_KEY =
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZg==";

    private TestTokens() {
    }

    static PropertiesProvider propertiesProvider() {
        return property -> SIGNING_KEY;
    }

    static String token(String subject, String role, long secondsUntilExpiry) {
        return token(subject, role, "CRUDE", null, secondsUntilExpiry, SIGNING_KEY);
    }

    static String token(String subject, String role, String permissions, String tenant, long secondsUntilExpiry, String signingKey) {
        return tokenWithIssuer(subject, role, permissions, tenant, secondsUntilExpiry, signingKey,
                SecurityConstants.Claims.EXPECTED_ISSUER);
    }

    static String tokenWithIssuer(String subject, String role, String permissions, String tenant,
                                  long secondsUntilExpiry, String signingKey, String issuer) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(signingKey));
        var builder = Jwts.builder()
                .subject(subject)
                .issuer(issuer)
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

    static String productionShapedToken(String subject, String role) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(HS512_SIGNING_KEY));
        return Jwts.builder()
                .subject(subject)
                .issuer(SecurityConstants.Claims.EXPECTED_ISSUER)
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(900)))
                .audience().add(List.of("trevorism.com")).and()
                .claim("role", role)
                .claim("dbId", "4856675479584768")
                .claim("entityType", "user")
                .claim("permissions", "CRE")
                .compressWith(Jwts.ZIP.GZIP)
                .signWith(key)
                .compact();
    }
}
