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

import java.net.http.HttpClient;
import java.time.Duration;
import org.jspecify.annotations.NullMarked;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The single outbound {@link HttpClient} (registry downloads and callbacks). Redirects are never
 * followed automatically: {@code ArtifactDownloader} follows them by hand so that every hop is
 * re-checked against {@code ArtifactUrlPolicy} -- an automatic redirect would let an allowed host
 * bounce a request to an internal address (SSRF).
 */
@Configuration
@NullMarked
public class HttpClientConfig {

    @Bean
    public HttpClient outboundHttpClient() {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }
}
