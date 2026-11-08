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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.silicaproxy.packagebehaviorguardian.FakeRegistry;
import com.silicaproxy.packagebehaviorguardian.ForwardingProxy;
import com.silicaproxy.packagebehaviorguardian.TestProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.CorporateProxyProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.CorporateProxyScope;
import java.io.IOException;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class CorporateProxyTest {

    private static CorporateProxy proxy(int port, String nonProxyHosts, CorporateProxyScope scope) {
        return new CorporateProxy(TestProperties.withCorporateProxy(
                new CorporateProxyProperties(true, "localhost", port, nonProxyHosts, scope)));
    }

    private static boolean proxied(java.net.ProxySelector selector, String uri) {
        return CorporateProxy.proxyFor(selector, URI.create(uri)).type() == Proxy.Type.HTTP;
    }

    @Test
    void disabledMeansDirectEverywhere() {
        CorporateProxy direct = new CorporateProxy(TestProperties.defaults());

        assertThat(proxied(direct.registries(), "https://registry.npmjs.org/x")).isFalse();
        assertThat(proxied(direct.gitRepository(), "https://git.example/repo.git")).isFalse();
        assertThat(proxied(direct.callbacks(), "http://silicaproxy:8080/cb")).isFalse();
    }

    @Test
    void eachCategoryFollowsItsScope() {
        CorporateProxy proxy = proxy(3128, "", new CorporateProxyScope(true, false, true));

        assertThat(proxied(proxy.registries(), "https://registry.npmjs.org/x")).isTrue();
        assertThat(proxied(proxy.gitRepository(), "https://git.example/repo.git")).isFalse();
        assertThat(proxied(proxy.callbacks(), "http://silicaproxy:8080/cb")).isTrue();
    }

    @Test
    void nonProxyHostsAreReachedDirectly() {
        java.net.ProxySelector registries = proxy(3128, "localhost | *.corp.local|::1", new CorporateProxyScope(true, true, true))
                .registries();

        assertThat(proxied(registries, "https://nexus.corp.local/repository/npm/x.tgz")).isFalse();
        assertThat(proxied(registries, "https://NEXUS.CORP.LOCAL/x")).isFalse();
        assertThat(proxied(registries, "http://localhost:8081/x")).isFalse();
        assertThat(proxied(registries, "http://[::1]:8081/x")).isFalse();
        assertThat(proxied(registries, "https://corp.local.evil.example/x")).isTrue();
        assertThat(proxied(registries, "https://registry.npmjs.org/x")).isTrue();
    }

    @Test
    void anEnabledProxyNeedsAHostAndAPort() {
        assertThatThrownBy(() -> new CorporateProxyProperties(true, " ", 3128, "", new CorporateProxyScope(true, false, false)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CorporateProxyProperties(true, "proxy", 0, "", new CorporateProxyScope(true, false, false)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void registriesGoThroughTheProxyAndCallbacksStayDirect() throws Exception {
        try (FakeRegistry registry = new FakeRegistry(); ForwardingProxy forwarding = new ForwardingProxy()) {
            registry.serve("/npm/left-pad/-/left-pad-1.3.0.tgz", "tarball".getBytes(StandardCharsets.UTF_8));
            CorporateProxy proxy = proxy(forwarding.port(), "", new CorporateProxyScope(true, false, false));
            HttpClientConfig config = new HttpClientConfig();
            String artifact = registry.url("/npm/left-pad/-/left-pad-1.3.0.tgz");

            try (HttpClient registries = config.registryHttpClient(proxy)) {
                HttpResponse<String> response = registries.send(HttpRequest.newBuilder(URI.create(artifact)).build(),
                        HttpResponse.BodyHandlers.ofString());
                assertThat(response.statusCode()).isEqualTo(200);
                assertThat(response.body()).isEqualTo("tarball");
            }
            assertThat(forwarding.requests()).containsExactly("GET " + artifact + " HTTP/1.1");

            try (HttpClient callbacks = config.callbackHttpClient(proxy)) {
                HttpResponse<String> response = callbacks.send(HttpRequest.newBuilder(URI.create(artifact)).build(),
                        HttpResponse.BodyHandlers.ofString());
                assertThat(response.statusCode()).isEqualTo(200);
            }
            assertThat(forwarding.requests()).hasSize(1);
        }
    }

    @Test
    void anUnreachableProxyFailsInsteadOfGoingDirect() throws Exception {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        try (FakeRegistry registry = new FakeRegistry();
                HttpClient registries = new HttpClientConfig().registryHttpClient(
                        proxy(closedPort, "", new CorporateProxyScope(true, false, false)))) {
            registry.serve("/x.tgz", new byte[] {1});

            assertThatThrownBy(() -> registries.send(HttpRequest.newBuilder(URI.create(registry.url("/x.tgz"))).build(),
                    HttpResponse.BodyHandlers.discarding()))
                    .isInstanceOf(IOException.class);
        }
    }
}
