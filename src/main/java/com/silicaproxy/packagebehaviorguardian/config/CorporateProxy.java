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


package com.silicaproxy.packagebehaviorguardian.config;

import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.CorporateProxyProperties;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * The company's outbound proxy ({@code corporate-proxy}), one {@link ProxySelector} per category of
 * outgoing traffic: the corporate proxy, except for the {@code non-proxy-hosts}, when the category is
 * in its scope; a direct connection otherwise. Never the JVM's default selector, so that neither the
 * {@code http.proxyHost} system properties nor another library's {@code ProxySelector.setDefault}
 * reroute a category this configuration keeps direct.
 */
@Component
@NullMarked
public class CorporateProxy {

    private static final Logger LOG = LoggerFactory.getLogger(CorporateProxy.class);

    private final ProxySelector registries;
    private final ProxySelector gitRepository;
    private final ProxySelector callbacks;

    public CorporateProxy(PackageBehaviorGuardianProperties properties) {
        CorporateProxyProperties config = properties.corporateProxy();
        ProxySelector proxied = HttpClient.Builder.NO_PROXY;
        if (config.enabled()) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved(String.valueOf(config.host()), config.port()));
            proxied = new Selector(proxy, NonProxyHosts.parse(config.nonProxyHosts()));
            LOG.info("Corporate proxy {}:{} (non-proxy hosts: {}) for registries: {}, Git repository: {}, callbacks: {}",
                    config.host(), config.port(), config.nonProxyHosts(), config.scope().registries(),
                    config.scope().gitRepository(), config.scope().callbacks());
        }
        this.registries = config.scope().registries() ? proxied : HttpClient.Builder.NO_PROXY;
        this.gitRepository = config.scope().gitRepository() ? proxied : HttpClient.Builder.NO_PROXY;
        this.callbacks = config.scope().callbacks() ? proxied : HttpClient.Builder.NO_PROXY;
    }

    public ProxySelector registries() {
        return registries;
    }

    public ProxySelector gitRepository() {
        return gitRepository;
    }

    public ProxySelector callbacks() {
        return callbacks;
    }

    /** The proxy {@code selector} picks for {@code uri}: the first one, {@link Proxy#NO_PROXY} if none. */
    public static Proxy proxyFor(ProxySelector selector, URI uri) {
        List<Proxy> proxies = selector.select(uri);
        return proxies.isEmpty() ? Proxy.NO_PROXY : proxies.getFirst();
    }

    /** {@code non-proxy-hosts}: "|"-separated host names, case-insensitive, "*" matching any characters. */
    record NonProxyHosts(List<Pattern> patterns) {

        static NonProxyHosts parse(String hosts) {
            return new NonProxyHosts(Arrays.stream(hosts.split("\\|"))
                    .map(String::strip)
                    .filter(host -> !host.isEmpty())
                    .map(host -> Pattern.compile(Arrays.stream(host.toLowerCase(Locale.ROOT).split("\\*", -1))
                            .map(Pattern::quote)
                            .reduce((left, right) -> left + ".*" + right)
                            .orElse("")))
                    .toList());
        }

        boolean matches(String host) {
            String lower = host.toLowerCase(Locale.ROOT);
            // [::1] in a URI, ::1 in the configuration.
            String bare = lower.startsWith("[") && lower.endsWith("]") ? lower.substring(1, lower.length() - 1) : lower;
            return patterns.stream().anyMatch(pattern -> pattern.matcher(lower).matches() || pattern.matcher(bare).matches());
        }
    }

    private static final class Selector extends ProxySelector {

        private final List<Proxy> proxy;
        private final NonProxyHosts nonProxyHosts;

        Selector(Proxy proxy, NonProxyHosts nonProxyHosts) {
            this.proxy = List.of(proxy);
            this.nonProxyHosts = nonProxyHosts;
        }

        @Override
        public List<Proxy> select(URI uri) {
            String host = uri.getHost();
            return host != null && nonProxyHosts.matches(host) ? List.of(Proxy.NO_PROXY) : proxy;
        }

        @Override
        public void connectFailed(URI uri, SocketAddress address, IOException failure) {
            // The caller reports the failure; there is no other proxy to fall back to.
        }
    }
}
