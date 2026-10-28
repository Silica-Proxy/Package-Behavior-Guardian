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


package com.silicaproxy.packagebehaviorguardian.controller;

import static org.assertj.core.api.Assertions.assertThat;

import com.silicaproxy.packagebehaviorguardian.BaseIntegrationTest;
import com.silicaproxy.packagebehaviorguardian.FakeRegistry;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * GuardDog and malcontent replaced by shell scripts printing canned JSON reports: exercises the
 * process runner, both scanners and both report parsers.
 */
@DisabledOnOs(OS.WINDOWS)
class ExternalScannersIntegrationTest extends BaseIntegrationTest {

    private static final FakeRegistry REGISTRY;
    private static final Path TOOLS;

    static {
        try {
            REGISTRY = new FakeRegistry();
            TOOLS = Files.createTempDirectory("pbg-fake-tools");
            script("guarddog", """
                    #!/bin/sh
                    case "$3" in
                      *evil-pkg*) echo '{"results": {}, "risk_score": {"score": 8.1, "label": "high_risk"}, "risks": [
                        {"threat_rule": "threat_runtime_obfuscation_base64exec", "severity": "high",
                         "threat_description": "Runs base64-decoded code", "threat_location": "package/index.js:3"}]}' ;;
                      *) echo '{"results": {}, "risk_score": {"score": 0.0, "label": "no_risks_detected"}, "risks": []}' ;;
                    esac
                    """);
            script("mal", """
                    #!/bin/sh
                    case "$4" in
                      *stealer*) echo '{"Files": {"package/index.js": {"RiskLevel": "CRITICAL", "Behaviors": [
                        {"ID": "exfil/stealer/browser", "Description": "steals browser cookies", "RiskLevel": "CRITICAL"}]}}}' ;;
                      *) echo '{"Files": {}}' ;;
                    esac
                    """);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        REGISTRY.serve("/npm/stealer/-/stealer-1.0.0.tgz", new byte[] {2});
        REGISTRY.serve("/npm/evil-pkg/-/evil-pkg-2.0.0.tgz", new byte[] {3});
    }

    private static void script(String name, String content) throws IOException {
        Path path = TOOLS.resolve(name);
        Files.writeString(path, content);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
    }

    @DynamicPropertySource
    static void scannerProperties(DynamicPropertyRegistry registry) {
        registry.add("packagebehaviorguardian.scanners.guarddog.enabled", () -> "true");
        registry.add("packagebehaviorguardian.scanners.guarddog.command", () -> TOOLS.resolve("guarddog").toString());
        registry.add("packagebehaviorguardian.scanners.malcontent.enabled", () -> "true");
        registry.add("packagebehaviorguardian.scanners.malcontent.command", () -> TOOLS.resolve("mal").toString());
    }

    @AfterAll
    static void stop() {
        REGISTRY.close();
    }

    @LocalServerPort
    private int port;

    private final HttpClient httpClient = HttpClient.newHttpClient();

    private void check(String name, String version, String callbackUrl) throws IOException, InterruptedException {
        String body = """
                {"packageName": "%s", "version": "%s", "ecosystem": "npm", "url": "%s", "callbackUrl": "%s"}
                """.formatted(name, version, REGISTRY.url("/npm/" + name + "/-/" + name + "-" + version + ".tgz"), callbackUrl);
        HttpResponse<String> response = httpClient.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v1/check"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(202);
    }

    private static String awaitCallbackBody(String callbackUrl) throws InterruptedException {
        String path = URI.create(callbackUrl).getPath();
        Instant deadline = Instant.now().plus(Duration.ofSeconds(30));
        while (Instant.now().isBefore(deadline)) {
            for (FakeRegistry.ReceivedCallback callback : REGISTRY.callbacks()) {
                if (callback.path().equals(path)) {
                    return callback.body();
                }
            }
            Thread.sleep(100);
        }
        throw new AssertionError("No callback received");
    }

    @Test
    void aCriticalGuardDogRuleBlocks() throws IOException, InterruptedException {
        String callbackUrl = REGISTRY.url("/callback/" + UUID.randomUUID());

        check("evil-pkg", "2.0.0", callbackUrl);

        assertThat(awaitCallbackBody(callbackUrl)).contains("\"verdict\":\"BLOCKED\"")
                .contains("BLOCKED by GDG-RISK (GuardDog rates the package high_risk (8.1/10): Runs base64-decoded code)");
    }

    @Test
    void aCriticalMalcontentFileBlocks() throws IOException, InterruptedException {
        String callbackUrl = REGISTRY.url("/callback/" + UUID.randomUUID());

        check("stealer", "1.0.0", callbackUrl);

        assertThat(awaitCallbackBody(callbackUrl)).contains("\"verdict\":\"BLOCKED\"")
                .contains("BLOCKED by BEH-071 (malcontent rates this file CRITICAL: steals browser cookies)");
    }
}
