package com.trevorism.ui;

import com.trevorism.ClaimsProvider;
import com.trevorism.PropertiesProvider;
import com.trevorism.micronaut.SecurityConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;

@Singleton
public class SessionClaimsReader {

    private static final Logger log = LoggerFactory.getLogger(SessionClaimsReader.class);
    private static final long CLOCK_SKEW_SECONDS = 120L;

    private final PropertiesProvider propertiesProvider;

    @Inject
    public SessionClaimsReader(PropertiesProvider propertiesProvider) {
        this.propertiesProvider = propertiesProvider;
    }

    public SessionClaims read(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        try {
            Claims claims = Jwts.parser()
                    .clockSkewSeconds(CLOCK_SKEW_SECONDS)
                    .verifyWith(signingKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return new SessionClaims(
                    claims.getSubject(),
                    claims.get(ClaimsProvider.ROLE, String.class),
                    claims.get(ClaimsProvider.PERMISSIONS, String.class),
                    claims.get(ClaimsProvider.TENANT, String.class),
                    toInstant(claims.getExpiration()));
        } catch (Exception e) {
            log.debug("Unable to read session claims: {}", e.getMessage());
            return null;
        }
    }

    private SecretKey signingKey() {
        String key = propertiesProvider.getProperty(SecurityConstants.Config.SIGNING_KEY);
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(key));
    }

    private static Instant toInstant(Date date) {
        return date == null ? null : date.toInstant();
    }
}
