package com.trevorism.ui;

import com.trevorism.http.HeadersHttpResponse;
import com.trevorism.http.HttpClient;
import com.trevorism.http.util.InvalidRequestException;

import java.util.Map;
import java.util.function.Function;

class StubHttpClient implements HttpClient {

    String lastUrl;
    String lastBody;
    private final Function<String, String> responder;

    StubHttpClient(String response) {
        this(url -> response);
    }

    StubHttpClient(Function<String, String> responder) {
        this.responder = responder;
    }

    static StubHttpClient failing(int statusCode) {
        return new StubHttpClient(url -> {
            throw new InvalidRequestException(new RuntimeException("boom"), statusCode);
        });
    }

    @Override
    public String post(String url, String serialized) {
        lastUrl = url;
        lastBody = serialized;
        return responder.apply(url);
    }

    @Override
    public String get(String url) {
        lastUrl = url;
        return responder.apply(url);
    }

    @Override
    public String put(String url, String serialized) {
        return post(url, serialized);
    }

    @Override
    public String patch(String url, String serialized) {
        return post(url, serialized);
    }

    @Override
    public String delete(String url) {
        return get(url);
    }

    @Override
    public HeadersHttpResponse get(String url, Map<String, String> headers) {
        return new HeadersHttpResponse(get(url));
    }

    @Override
    public HeadersHttpResponse post(String url, String serialized, Map<String, String> headers) {
        return new HeadersHttpResponse(post(url, serialized));
    }

    @Override
    public HeadersHttpResponse put(String url, String serialized, Map<String, String> headers) {
        return new HeadersHttpResponse(put(url, serialized));
    }

    @Override
    public HeadersHttpResponse patch(String url, String serialized, Map<String, String> headers) {
        return new HeadersHttpResponse(patch(url, serialized));
    }

    @Override
    public HeadersHttpResponse delete(String url, Map<String, String> headers) {
        return new HeadersHttpResponse(delete(url));
    }
}
