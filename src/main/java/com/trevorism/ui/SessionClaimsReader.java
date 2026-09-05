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
import java.util.concurrent.atomic.AtomicBoolean;

@Singleton
public class SessionClaimsReader {

    private static final Logger log = LoggerFactory.getLogger(SessionClaimsReader.class);
    private static final long CLOCK_SKEW_SECONDS = 120L;
    private static final String UNUSABLE_KEY_MESSAGE =
            "Cannot verify sessions because {} is unusable, {}. Every user will appear signed out until this is fixed.";

    private final PropertiesProvider propertiesProvider;
    private final AtomicBoolean unusableKeyReported = new AtomicBoolean();

    @Inject
    public SessionClaimsReader(PropertiesProvider propertiesProvider) {
        this.propertiesProvider = propertiesProvider;
    }

    public SessionClaims read(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        SecretKey key = signingKey();
        if (key == null) {
            return null;
        }
        try {
            Claims claims = Jwts.parser()
                    .clockSkewSeconds(CLOCK_SKEW_SECONDS)
                    .requireIssuer(SecurityConstants.Claims.EXPECTED_ISSUER)
                    .verifyWith(key)
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
            log.debug("Session token did not verify: {}", e.getMessage());
            return null;
        }
    }

    private SecretKey signingKey() {
        String key = readSigningKeyProperty();
        if (key == null || key.isBlank()) {
            reportUnusableKey("no value is available on the classpath");
            return null;
        }
        try {
            return Keys.hmacShaKeyFor(Decoders.BASE64.decode(key));
        } catch (Exception e) {
            reportUnusableKey("the configured value was rejected: " + e.getMessage());
            return null;
        }
    }

    private String readSigningKeyProperty() {
        try {
            return propertiesProvider.getProperty(SecurityConstants.Config.SIGNING_KEY);
        } catch (Exception e) {
            reportUnusableKey("reading it failed: " + e.getMessage());
            return null;
        }
    }

    private void reportUnusableKey(String detail) {
        if (unusableKeyReported.compareAndSet(false, true)) {
            log.error(UNUSABLE_KEY_MESSAGE, SecurityConstants.Config.SIGNING_KEY, detail);
        } else {
            log.debug(UNUSABLE_KEY_MESSAGE, SecurityConstants.Config.SIGNING_KEY, detail);
        }
    }

    private static Instant toInstant(Date date) {
        return date == null ? null : date.toInstant();
    }
}
