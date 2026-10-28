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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

@Component
@NullMarked
public class ApiKeyValidator {

    private final PackageBehaviorGuardianProperties properties;

    public ApiKeyValidator(PackageBehaviorGuardianProperties properties) {
        this.properties = properties;
    }

    public boolean isAuthorized(Scope scope, @Nullable String providedKey) {
        if (!properties.security().enabled()) {
            return true;
        }
        String expectedKey = switch (scope) {
            case CHECK -> properties.security().apiKey();
            case REPORT -> properties.security().reportApiKey();
        };
        return constantTimeEquals(expectedKey, providedKey);
    }

    // Fails closed (returns false) when no key is configured: a missing secret must not
    // silently open the endpoint once the api-key check is enabled. Digests are compared, so the
    // comparison takes the same time whatever the length of the key provided.
    private static boolean constantTimeEquals(@Nullable String expected, @Nullable String actual) {
        if (expected == null || expected.isBlank() || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(sha256(expected), sha256(actual));
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is mandatory in every JRE", e);
        }
    }
}
