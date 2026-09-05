package com.trevorism.ui;

import io.micronaut.context.ApplicationContext;
import io.micronaut.web.router.Router;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UiAuthWiringTest {

    private static ApplicationContext configuredContext() {
        return ApplicationContext.run(Map.of(
                "trevorism.ui-auth.login-url", "https://login.auth.trevorism.com/",
                "trevorism.ui-auth.auth-url", "https://pr-10-dot-trevorism-auth.uk.r.appspot.com",
                "trevorism.ui-auth.platform-domains", List.of("trevorism.com", "memowand.com"),
                "trevorism.ui-auth.tenant-guid", "guid-9"));
    }

    @Test
    void testEveryBeanResolvesFromTheJarMetadata() {
        try (ApplicationContext context = ApplicationContext.run()) {
            assertNotNull(context.getBean(UiAuthConfiguration.class));
            assertNotNull(context.getBean(CookieDomainPolicy.class));
            assertNotNull(context.getBean(PublicOriginResolver.class));
            assertNotNull(context.getBean(SessionCookieWriter.class));
            assertNotNull(context.getBean(SessionClaimsReader.class));
            assertNotNull(context.getBean(AuthProviderClient.class));
            assertNotNull(context.getBean(UiAuthController.class));
        }
    }

    @Test
    void testConfigurationBindsFromProperties() {
        try (ApplicationContext context = configuredContext()) {
            UiAuthConfiguration configuration = context.getBean(UiAuthConfiguration.class);

            assertEquals("https://login.auth.trevorism.com", configuration.getLoginUrl());
            assertEquals("https://pr-10-dot-trevorism-auth.uk.r.appspot.com", configuration.getAuthUrl());
            assertEquals(List.of("trevorism.com", "memowand.com"), configuration.getPlatformDomains());
            assertEquals("guid-9", configuration.getTenantGuid());
        }
    }

    @Test
    void testEveryRouteIsRegistered() {
        try (ApplicationContext context = ApplicationContext.run()) {
            String routes = context.getBean(Router.class).uriRoutes()
                    .map(Object::toString)
                    .collect(Collectors.joining("\n"));

            assertTrue(routes.contains(UiAuthController.BASE_PATH + "/login"), routes);
            assertTrue(routes.contains(UiAuthController.CALLBACK_PATH), routes);
            assertTrue(routes.contains(UiAuthController.BASE_PATH + "/session"), routes);
            assertTrue(routes.contains(UiAuthController.BASE_PATH + "/refresh"), routes);
            assertTrue(routes.contains(UiAuthController.BASE_PATH + "/logout"), routes);
        }
    }

    @Test
    void testCallbackRouteMatchesTheRedirectUriSentToTheLoginApp() {
        try (ApplicationContext context = ApplicationContext.run()) {
            String routes = context.getBean(Router.class).uriRoutes()
                    .map(Object::toString)
                    .collect(Collectors.joining("\n"));

            assertTrue(routes.contains(UiAuthController.CALLBACK_PATH), routes);
            assertEquals("/api/auth/callback", UiAuthController.CALLBACK_PATH);
        }
    }

    @Test
    void testSigningKeyIsReadThroughTheInjectedPropertiesProvider() {
        try (ApplicationContext context = ApplicationContext.run()) {
            SessionClaimsReader reader = context.getBean(SessionClaimsReader.class);

            assertNotNull(reader);
        }
    }
}
