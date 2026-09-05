package com.trevorism.ui;

public record PublicOrigin(String scheme, String host) {

    private static final String HTTP = "http";

    public String origin() {
        return scheme + "://" + host;
    }

    public String hostname() {
        if (host.startsWith("[")) {
            int end = host.indexOf(']');
            return end < 0 ? host : host.substring(0, end + 1);
        }
        int colon = host.indexOf(':');
        return colon < 0 ? host : host.substring(0, colon);
    }

    public boolean isLoopback() {
        String hostname = hostname().toLowerCase();
        return hostname.equals("localhost") || hostname.equals("127.0.0.1") || hostname.equals("[::1]");
    }

    public boolean requiresSecureCookies() {
        return !(HTTP.equalsIgnoreCase(scheme) && isLoopback());
    }
}
