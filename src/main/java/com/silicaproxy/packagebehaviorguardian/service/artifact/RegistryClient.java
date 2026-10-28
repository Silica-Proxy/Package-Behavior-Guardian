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


package com.silicaproxy.packagebehaviorguardian.service.artifact;

import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Lists every file of a PyPI version ({@code /pypi/{name}/{version}/json}), through {@link ArtifactDownloader}. */
@Component
@NullMarked
public class RegistryClient {

    private final ArtifactDownloader downloader;
    private final ObjectMapper objectMapper;
    private final String pypiUrl;

    public RegistryClient(ArtifactDownloader downloader, ObjectMapper objectMapper, PackageBehaviorGuardianProperties properties) {
        this.downloader = downloader;
        this.objectMapper = objectMapper;
        this.pypiUrl = properties.registries().pypiUrl().replaceAll("/+$", "");
    }

    public List<String> pypiVersionFiles(String name, String version) throws IOException {
        URI url = URI.create(pypiUrl + "/pypi/" + encode(name) + "/" + encode(version) + "/json");
        return pypiVersionFiles(objectMapper.readTree(downloader.fetchMetadata(url)));
    }

    // Untrusted input: odd or missing fields are skipped. Yanked files are kept: pip still installs
    // them when the exact version is pinned (PEP 592), so a malicious yanked wheel must not hide.
    static List<String> pypiVersionFiles(JsonNode versionJson) {
        List<String> urls = new ArrayList<>();
        for (JsonNode file : versionJson.path("urls")) {
            String url = file.path("url").asString("");
            if (!url.isEmpty()) {
                urls.add(url);
            }
        }
        return urls;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
