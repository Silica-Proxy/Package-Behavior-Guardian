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


package com.silicaproxy.packagebehaviorguardian.service.callback;

import com.silicaproxy.packagebehaviorguardian.model.dto.CallbackPayload;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.service.intake.UrlPolicy;
import com.silicaproxy.packagebehaviorguardian.service.intake.UrlRejectedException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * POSTs one verdict to a SilicaProxy callback URL with {@code Authorization: Bearer
 * <security.api-key>}: SilicaProxy checks the callback with the same per-service key it sends us. The URL is re-checked against the callback host
 * allowlist at send time, in case the configuration changed since the check request.
 */
@Component
@NullMarked
public class CallbackSender {

    /** The URL is no longer allowed: never sent. */
    public static final int REJECTED = -2;
    /** Network error or timeout. */
    public static final int TRANSPORT_ERROR = -1;

    private static final Logger LOG = LoggerFactory.getLogger(CallbackSender.class);

    private final UrlPolicy urlPolicy;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final String apiKey;

    public CallbackSender(UrlPolicy urlPolicy, HttpClient httpClient, ObjectMapper objectMapper,
            PackageBehaviorGuardianProperties properties) {
        this.urlPolicy = urlPolicy;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        String key = properties.security().apiKey();
        this.apiKey = key == null ? "" : key;
    }

    /** HTTP status, {@link #REJECTED} or {@link #TRANSPORT_ERROR}. */
    public int send(String callbackUrl, CallbackPayload payload) {
        URI url;
        try {
            url = urlPolicy.requireCallbackUrl(callbackUrl);
        } catch (UrlRejectedException e) {
            LOG.warn("Callback URL refused at send time: {}", e.getMessage());
            return REJECTED;
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(url)
                .timeout(TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)));
        if (!apiKey.isBlank()) {
            request.header("Authorization", "Bearer " + apiKey);
        }
        try {
            return httpClient.send(request.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
        } catch (IOException e) {
            LOG.warn("Callback to {} failed: {}", url.getHost(), e.getMessage());
            return TRANSPORT_ERROR;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return TRANSPORT_ERROR;
        }
    }
}
