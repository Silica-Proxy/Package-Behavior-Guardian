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


package com.silicaproxy.packagebehaviorguardian.service.report;

import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

/**
 * Builds the report link appended to every reason sent to SilicaProxy. Query parameters rather than
 * path segments: npm scoped names contain a '/'.
 */
@Component
@NullMarked
public class ReportLinks {

    private final String publicBaseUrl;

    public ReportLinks(PackageBehaviorGuardianProperties properties) {
        String base = properties.analysis().publicBaseUrl();
        this.publicBaseUrl = base == null ? "" : base.replaceAll("/+$", "");
    }

    /** {@code " — report: <url>"}, or empty when no public base URL is configured. */
    public String suffix(String ecosystem, String name, String version) {
        if (publicBaseUrl.isEmpty()) {
            return "";
        }
        return " — report: " + publicBaseUrl + "/v1/reports?ecosystem=" + encode(ecosystem)
                + "&name=" + encode(name) + "&version=" + encode(version);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
