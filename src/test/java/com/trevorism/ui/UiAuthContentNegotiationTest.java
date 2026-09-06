package com.trevorism.ui;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.MediaType;
import io.micronaut.web.router.Router;
import io.micronaut.web.router.UriRouteInfo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

// A POST here carries no body, so it must not care what the caller says it is
// sending. Axios posts a bodyless request as form-urlencoded, and Micronaut
// defaults @Post to consuming application/json, which answered 415 and left
// logout and refresh doing nothing in the browser.
class UiAuthContentNegotiationTest {

    private static final MediaType[] WHAT_BROWSERS_SEND = {
            MediaType.APPLICATION_FORM_URLENCODED_TYPE,
            MediaType.TEXT_PLAIN_TYPE,
            MediaType.MULTIPART_FORM_DATA_TYPE,
            MediaType.APPLICATION_JSON_TYPE,
    };

    private static UriRouteInfo<?, ?> routeFor(ApplicationContext context, String path) {
        return context.getBean(Router.class).uriRoutes()
                .filter(route -> route.toString().contains(path))
                .findFirst()
                .orElseGet(() -> fail("No route registered for " + path));
    }

    private static void assertAcceptsAnyContentType(String path) {
        try (ApplicationContext context = ApplicationContext.run()) {
            UriRouteInfo<?, ?> route = routeFor(context, path);

            for (MediaType contentType : WHAT_BROWSERS_SEND) {
                assertTrue(route.doesConsume(contentType),
                        path + " refuses " + contentType + ", which the browser answers as 415; it takes no body, so it must consume anything");
            }
            assertTrue(route.doesConsume(null), path + " must accept a request that declares no content type at all");
        }
    }

    @Test
    void testLogoutAcceptsWhateverContentTypeTheBrowserAttaches() {
        assertAcceptsAnyContentType(UiAuthController.BASE_PATH + "/logout");
    }

    @Test
    void testRefreshAcceptsWhateverContentTypeTheBrowserAttaches() {
        assertAcceptsAnyContentType(UiAuthController.BASE_PATH + "/refresh");
    }
}
