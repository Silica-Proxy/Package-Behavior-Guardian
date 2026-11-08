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

import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.time.Duration;
import org.jspecify.annotations.NullMarked;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * One client per category of outgoing traffic, each with its own route ({@link CorporateProxy}):
 * registries ({@value #REGISTRY_CLIENT}, the default one) and SilicaProxy callbacks ({@value #CALLBACK_CLIENT}).
 * Redirects are never followed by the client: each hop is checked against the host allowlists.
 */
@Configuration
@NullMarked
public class HttpClientConfig {

    public static final String REGISTRY_CLIENT = "registryHttpClient";
    public static final String CALLBACK_CLIENT = "callbackHttpClient";

    @Bean(REGISTRY_CLIENT)
    @Primary
    public HttpClient registryHttpClient(CorporateProxy corporateProxy) {
        return client(corporateProxy.registries());
    }

    @Bean(CALLBACK_CLIENT)
    public HttpClient callbackHttpClient(CorporateProxy corporateProxy) {
        return client(corporateProxy.callbacks());
    }

    static HttpClient client(ProxySelector route) {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .proxy(route)
                .build();
    }
}
