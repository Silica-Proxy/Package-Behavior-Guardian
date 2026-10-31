/*
 * Copyright 2026 SilicaProxy Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.silicaproxy.packagebehaviorguardian.service.intake;

import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

/**
 * Anti-SSRF gate for every URL this service fetches or POSTs to. A URL is accepted only if it is
 * absolute, https (http only when {@code intake.allow-http-callbacks} / {@code allow-http-artifacts}),
 * carries no user info, and its host -- or {@code host:port} for a non-default port -- is exactly
 * one of the configured entries ({@code host:*} accepts any port of that host; meant for local
 * development and tests). Called on the request URLs and again on every redirect hop and every
 * derived URL (PyPI file list, Maven main artifact), since those come from registry responses.
 */
@Component
@NullMarked
public class UrlPolicy {

    private final PackageBehaviorGuardianProperties.IntakeProperties properties;

    public UrlPolicy(PackageBehaviorGuardianProperties properties) {
        this.properties = properties.intake();
    }

    public URI requireArtifactUrl(String url) {
        return require(url, properties.allowedArtifactHosts(), properties.allowHttpArtifacts(), "artifact");
    }

    public URI requireCallbackUrl(String url) {
        return require(url, properties.allowedCallbackHosts(), properties.allowHttpCallbacks(), "callback");
    }

    private static String defaultPort(String scheme) {
        return "https".equals(scheme) ? ":443" : ":80";
    }

    private static String authority(String host, int port, String scheme) {
        return port == -1 || defaultPort(scheme).equals(":" + port) ? host : host + ":" + port;
    }

    // An entry naming the scheme's default port explicitly ("host:443") means the bare host.
    private static boolean isAllowed(String host, String authority, String scheme, List<String> allowedHosts) {
        String defaultPort = defaultPort(scheme);
        return allowedHosts.stream()
                .map(entry -> entry.trim().toLowerCase(Locale.ROOT))
                .map(entry -> entry.endsWith(defaultPort) ? entry.substring(0, entry.length() - defaultPort.length()) : entry)
                .anyMatch(entry -> entry.equals(authority) || entry.endsWith(":*") && entry.equals(host + ":*"));
    }

    /**
     * Whether the host of an absolute URL is one of {@code entries}, with the semantics of the host
     * allowlists ({@code host}, {@code host:port}, {@code host:*}).
     */
    public static boolean hostMatches(URI uri, List<String> entries) {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (uri.getHost() == null) {
            return false;
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        return isAllowed(host, authority(host, uri.getPort(), scheme), scheme, entries);
    }

    /** {@code host}, or {@code host:port} for a non-default port: the form the host allowlists use. */
    public static String authorityOf(URI uri) {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        return authority(host, uri.getPort(), scheme);
    }

    private URI require(String url, List<String> allowedHosts, boolean allowHttp, String kind) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new UrlRejectedException("Malformed " + kind + " URL");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        boolean schemeAllowed = "https".equals(scheme) || "http".equals(scheme) && allowHttp;
        if (!uri.isAbsolute() || !schemeAllowed) {
            throw new UrlRejectedException("The " + kind + " URL must be an absolute https URL");
        }
        if (uri.getHost() == null || uri.getRawUserInfo() != null) {
            throw new UrlRejectedException("The " + kind + " URL must have a host and no user info");
        }
        if (!hostMatches(uri, allowedHosts)) {
            throw new UrlRejectedException("The " + kind + " URL host is not allowed: " + authorityOf(uri));
        }
        return uri;
    }
}
