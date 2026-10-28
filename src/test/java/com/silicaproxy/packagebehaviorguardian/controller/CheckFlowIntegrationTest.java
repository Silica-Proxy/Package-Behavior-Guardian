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
import com.silicaproxy.packagebehaviorguardian.FakeRegistry.ReceivedCallback;
import com.silicaproxy.packagebehaviorguardian.TestJars;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * The whole asynchronous contract with SilicaProxy, against a real database and a fake registry:
 * check (202) → static analysis by the worker → callback with the verdict; then the cached path
 * (200 + immediate callback), the report, and an allowlist entry flipping the verdict.
 */
class CheckFlowIntegrationTest extends BaseIntegrationTest {

    private static FakeRegistry registry;

    @LocalServerPort
    private int port;

    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeAll
    static void startRegistry() throws IOException {
        registry = new FakeRegistry();
        String dir = "/maven2/com/evil/payload/1.0/";
        registry.serve(dir + "payload-1.0.pom", "<project/>".getBytes(StandardCharsets.UTF_8));
        registry.serve(dir + "payload-1.0.jar", TestJars.jar(TestJars.entries(
                "com/evil/Init.class", TestJars.classWithExecInStaticInitializer("com/evil/Init"))));
        registry.serve("/maven2/org/example/clean/2.0/clean-2.0.pom", "<project/>".getBytes(StandardCharsets.UTF_8));
        registry.serve("/maven2/org/example/clean/2.0/clean-2.0.jar", TestJars.jar(TestJars.entries(
                "org/example/Clean.class", TestJars.classCalling("org/example/Clean", "java/lang/Object", new String[0]))));
        registry.serve("/maven2/org/example/bom/1.0/bom-1.0.pom",
                "<project><packaging>pom</packaging></project>".getBytes(StandardCharsets.UTF_8));
        registry.serve("/maven2/org/example/nojar/1.0/nojar-1.0.pom", "<project/>".getBytes(StandardCharsets.UTF_8));
        String classified = "/maven2/org/example/classified/1.0/";
        registry.serve(classified + "classified-1.0.pom", "<project/>".getBytes(StandardCharsets.UTF_8));
        registry.serve(classified + "classified-1.0.jar", TestJars.jar(TestJars.entries(
                "org/example/Clean.class", TestJars.classCalling("org/example/Clean", "java/lang/Object", new String[0]))));
        registry.serve(classified + "classified-1.0-linux-x86_64.jar", TestJars.jar(TestJars.entries(
                "org/example/Native.class", TestJars.classWithExecInStaticInitializer("org/example/Native"))));
        registry.serve("/npm/left-pad/-/left-pad-1.3.0.tgz", new byte[] {0x1f, (byte) 0x8b});
        registry.serve("/maven2/com/evil/broken/1.0/broken-1.0.pom", "<project/>".getBytes(StandardCharsets.UTF_8));
        registry.serve("/maven2/com/evil/broken/1.0/broken-1.0.jar", TestJars.jar(TestJars.entries(
                "com/evil/Broken.class", new byte[] {(byte) 0xCA, (byte) 0xFE, 1, 2, 3})));
    }

    @AfterAll
    static void stopRegistry() {
        registry.close();
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws IOException, InterruptedException {
        return httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> check(String name, String version, String ecosystem, String url, String callbackUrl)
            throws IOException, InterruptedException {
        String body = """
                {"packageName": "%s", "version": "%s", "ecosystem": "%s", "url": "%s", "callbackUrl": "%s"}
                """.formatted(name, version, ecosystem, url, callbackUrl);
        return send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v1/check"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)));
    }

    private HttpResponse<String> report(String ecosystem, String name, String version) throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v1/reports?ecosystem=" + ecosystem
                + "&name=" + URLEncoder.encode(name, StandardCharsets.UTF_8) + "&version=" + version)).GET());
    }

    private static String newCallbackUrl() {
        return registry.url("/callback/" + UUID.randomUUID());
    }

    private static ReceivedCallback awaitCallback(String callbackUrl) throws InterruptedException {
        String path = URI.create(callbackUrl).getPath();
        return awaitCallback(callback -> callback.path().equals(path));
    }

    private static ReceivedCallback awaitCallback(Predicate<ReceivedCallback> match) throws InterruptedException {
        Instant deadline = Instant.now().plus(Duration.ofSeconds(30));
        while (Instant.now().isBefore(deadline)) {
            List<ReceivedCallback> found = registry.callbacks().stream().filter(match).toList();
            if (!found.isEmpty()) {
                return found.get(0);
            }
            Thread.sleep(100);
        }
        throw new AssertionError("No callback received");
    }

    @Test
    void aMaliciousJarIsBlockedByCallbackThenServedFromTheCache() throws IOException, InterruptedException {
        String pomUrl = registry.url("/maven2/com/evil/payload/1.0/payload-1.0.pom");
        String firstCallback = newCallbackUrl();

        HttpResponse<String> first = check("com.evil:payload", "1.0", "maven", pomUrl, firstCallback);

        assertThat(first.statusCode()).isEqualTo(202);
        assertThat(first.body()).contains("\"status\":\"PENDING\"");
        ReceivedCallback callback = awaitCallback(firstCallback);
        assertThat(callback.body()).contains("\"verdict\":\"BLOCKED\"").contains("BLOCKED by JVM-001")
                .contains("https://pbg.test/v1/reports?ecosystem=maven&name=com.evil%3Apayload&version=1.0");

        String secondCallback = newCallbackUrl();
        HttpResponse<String> second = check("com.evil:payload", "1.0", "maven", pomUrl, secondCallback);

        assertThat(second.statusCode()).isEqualTo(200);
        assertThat(second.body()).contains("\"verdict\":\"BLOCKED\"");
        assertThat(awaitCallback(secondCallback).body()).contains("\"verdict\":\"BLOCKED\"");

        HttpResponse<String> report = report("maven", "com.evil:payload", "1.0");
        assertThat(report.statusCode()).isEqualTo(200);
        assertThat(report.body()).contains("\"status\":\"DONE\"").contains("\"ruleId\":\"JVM-001\"")
                .contains("payload-1.0.jar").contains("\"sha256\"");
    }

    @Test
    void aConfiguredAllowlistEntrySetsTheFindingAside() throws IOException, InterruptedException {
        // application-test.yaml allowlists JVM-001 for com.evil:allowed (and only for it).
        registry.serve("/maven2/com/evil/allowed/1.0/allowed-1.0.pom", "<project/>".getBytes(StandardCharsets.UTF_8));
        registry.serve("/maven2/com/evil/allowed/1.0/allowed-1.0.jar", TestJars.jar(TestJars.entries(
                "com/evil/Init.class", TestJars.classWithExecInStaticInitializer("com/evil/Init"))));
        String callbackUrl = newCallbackUrl();

        check("com.evil:allowed", "1.0", "maven", registry.url("/maven2/com/evil/allowed/1.0/allowed-1.0.jar"), callbackUrl);

        assertThat(awaitCallback(callbackUrl).body()).contains("\"verdict\":\"ALLOWED\"");
        assertThat(report("maven", "com.evil:allowed", "1.0").body()).contains("\"allowlistedFindings\":[{\"ruleId\":\"JVM-001\"");
    }

    @Test
    void aCleanJarIsAllowed() throws IOException, InterruptedException {
        String callbackUrl = newCallbackUrl();

        check("org.example:clean", "2.0", "maven", registry.url("/maven2/org/example/clean/2.0/clean-2.0.pom"), callbackUrl);

        assertThat(awaitCallback(callbackUrl).body()).contains("\"verdict\":\"ALLOWED\"")
                .contains("No suspicious behavior found by the static pass");
    }

    @Test
    void aPomOnlyArtifactIsAllowedWithNothingToAnalyze() throws IOException, InterruptedException {
        String callbackUrl = newCallbackUrl();

        check("org.example:bom", "1.0", "maven", registry.url("/maven2/org/example/bom/1.0/bom-1.0.pom"), callbackUrl);

        assertThat(awaitCallback(callbackUrl).body()).contains("\"verdict\":\"ALLOWED\"");
        assertThat(report("maven", "org.example:bom", "1.0").body()).contains("\"artifacts\":[]");
    }

    @Test
    void aRequestedClassifierJarIsAnalyzedBesidesTheMainOne() throws IOException, InterruptedException {
        String callbackUrl = newCallbackUrl();

        check("org.example:classified", "1.0", "maven", registry.url("/maven2/org/example/classified/1.0/classified-1.0-linux-x86_64.jar"),
                callbackUrl);

        assertThat(awaitCallback(callbackUrl).body()).contains("\"verdict\":\"BLOCKED\"").contains("JVM-001");
        assertThat(report("maven", "org.example:classified", "1.0").body())
                .contains("classified-1.0.jar").contains("classified-1.0-linux-x86_64.jar");
    }

    @Test
    void aPackageThatPreventsItsOwnAnalysisIsBlockedNotFailedOpen() throws IOException, InterruptedException {
        String callbackUrl = newCallbackUrl();

        check("com.evil:broken", "1.0", "maven", registry.url("/maven2/com/evil/broken/1.0/broken-1.0.pom"), callbackUrl);

        assertThat(awaitCallback(callbackUrl).body()).contains("\"verdict\":\"BLOCKED\"")
                .contains("BLOCKED by PBG-001 (Analysis impossible: Malformed class file in jar)");
    }

    @Test
    void aJarPackagedArtifactWithoutItsJarFailsInsteadOfPassing() throws IOException, InterruptedException {
        check("org.example:nojar", "1.0", "maven", registry.url("/maven2/org/example/nojar/1.0/nojar-1.0.pom"), newCallbackUrl());

        Instant deadline = Instant.now().plus(Duration.ofSeconds(30));
        String body = "";
        while (Instant.now().isBefore(deadline) && !body.contains("\"status\":\"FAILED\"")) {
            Thread.sleep(200);
            body = report("maven", "org.example:nojar", "1.0").body();
        }
        assertThat(body).contains("\"status\":\"FAILED\"").contains("nojar-1.0.jar");
    }

    @Test
    void anNpmPackageIsDownloadedAndAnalyzedByTheEnabledScanners() throws IOException, InterruptedException {
        String callbackUrl = newCallbackUrl();

        check("left-pad", "1.3.0", "npm", registry.url("/npm/left-pad/-/left-pad-1.3.0.tgz"), callbackUrl);

        // GuardDog and malcontent are disabled in tests: the download still happens and is reported.
        assertThat(awaitCallback(callbackUrl).body()).contains("\"verdict\":\"ALLOWED\"");
        assertThat(report("npm", "left-pad", "1.3.0").body()).contains("left-pad-1.3.0.tgz");
    }

    @Test
    void aMissingArtifactFailsTheJobAndSendsNoVerdict() throws IOException, InterruptedException {
        String callbackUrl = newCallbackUrl();

        check("ghost", "1.0.0", "npm", registry.url("/npm/ghost/-/ghost-1.0.0.tgz"), callbackUrl);

        Instant deadline = Instant.now().plus(Duration.ofSeconds(30));
        String body = "";
        while (Instant.now().isBefore(deadline) && !body.contains("\"status\":\"FAILED\"")) {
            Thread.sleep(200);
            body = report("npm", "ghost", "1.0.0").body();
        }
        assertThat(body).contains("\"status\":\"FAILED\"").contains("\"attempts\":3").contains("Not found");
        String path = URI.create(callbackUrl).getPath();
        assertThat(registry.callbacks()).noneMatch(callback -> callback.path().equals(path));
    }

    @Test
    void aCallbackHostOutsideTheAllowlistIsRefused() throws IOException, InterruptedException {
        HttpResponse<String> response = check("left-pad", "1.3.0", "npm",
                registry.url("/npm/left-pad/-/left-pad-1.3.0.tgz"), "http://169.254.169.254/latest/meta-data");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("The callback URL host is not allowed: 169.254.169.254");
    }

    @Test
    void anArtifactHostOutsideTheAllowlistIsRefused() throws IOException, InterruptedException {
        HttpResponse<String> response = check("left-pad", "1.3.0", "npm",
                "http://10.0.0.1/left-pad-1.3.0.tgz", newCallbackUrl());

        assertThat(response.statusCode()).isEqualTo(400);
    }

    @Test
    void aMalformedMavenNameIsRefused() throws IOException, InterruptedException {
        HttpResponse<String> response = check("no-colon", "1.0", "maven",
                registry.url("/maven2/no-colon/1.0/no-colon-1.0.pom"), newCallbackUrl());

        assertThat(response.statusCode()).isEqualTo(400);
    }

    @Test
    void anUnknownReportIs404() throws IOException, InterruptedException {
        assertThat(report("npm", "never-checked", "1.0.0").statusCode()).isEqualTo(404);
    }
}
