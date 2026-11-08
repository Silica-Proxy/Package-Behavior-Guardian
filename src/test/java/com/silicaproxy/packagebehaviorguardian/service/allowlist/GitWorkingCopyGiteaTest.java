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


package com.silicaproxy.packagebehaviorguardian.service.allowlist;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.silicaproxy.packagebehaviorguardian.ForwardingProxy;
import com.silicaproxy.packagebehaviorguardian.TestProperties;
import com.silicaproxy.packagebehaviorguardian.config.CorporateProxy;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AllowlistRepository.StoredEntry;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.CorporateProxyProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.CorporateProxyScope;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.GitOpsProperties;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import tools.jackson.databind.ObjectMapper;

/**
 * {@link GitWorkingCopy} against a real Gitea over HTTP, as in production: shallow fetch through the
 * smart HTTP protocol, a public repository, a private one reached with a token (and refused without
 * it), a non-default branch, a later commit picked up by the next update, and the corporate proxy.
 */
class GitWorkingCopyGiteaTest {

    private static final String ADMIN = "testadmin";
    private static final String PASSWORD = "T3stP@ss!";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String ESBUILD = """
            allowlist:
              - name: esbuild
                rule-id: GDG-RISK
                reason: downloads its platform binary at install
            """;

    @SuppressWarnings("resource")
    private static final GenericContainer<?> GITEA = new GenericContainer<>(DockerImageName.parse("gitea/gitea:1.26"))
            .withExposedPorts(3000)
            .withEnv("GITEA__security__INSTALL_LOCK", "true")
            .withEnv("GITEA__server__DOMAIN", "localhost")
            .withEnv("GITEA__server__HTTP_PORT", "3000")
            .withEnv("GITEA__database__DB_TYPE", "sqlite3")
            .withEnv("GITEA__security__PASSWORD_COMPLEXITY", "off")
            .withEnv("GITEA__log__LEVEL", "Error")
            .waitingFor(Wait.forHttp("/api/v1/version").withStartupTimeout(Duration.ofMinutes(2)));

    private static String baseUrl;
    private static String token;

    private final GitWorkingCopy workingCopy = new GitWorkingCopy(new CorporateProxy(TestProperties.defaults()));

    @TempDir
    Path temp;

    static {
        GITEA.start();
    }

    @BeforeAll
    static void setUpGitea() throws Exception {
        baseUrl = "http://" + GITEA.getHost() + ":" + GITEA.getMappedPort(3000);
        // PID 1 runs as root and the gitea binary refuses to: run it as the image's git user.
        Container.ExecResult created = GITEA.execInContainer("/sbin/su-exec", "git", "gitea", "admin", "user", "create",
                "--username", ADMIN, "--password", PASSWORD, "--email", "admin@test.local", "--admin");
        if (created.getExitCode() != 0) {
            throw new IllegalStateException("Could not create the Gitea admin: " + created.getStdout() + created.getStderr());
        }
        token = JSON.readTree(api("POST", "/api/v1/users/" + ADMIN + "/tokens",
                "{\"name\":\"pbg-test\",\"scopes\":[\"read:repository\"]}")).get("sha1").asString();

        createRepo("allowlist-public", false);
        putFile("allowlist-public", "npm.yaml", ESBUILD, null);
        createRepo("allowlist-private", true);
        putFile("allowlist-private", "pbg/npm.yaml", ESBUILD, null);
        api("POST", "/api/v1/repos/" + ADMIN + "/allowlist-private/branches",
                "{\"new_branch_name\":\"reviewed\",\"old_branch_name\":\"main\"}");
        putFile("allowlist-private", "pbg/pypi.yaml", "allowlist:\n  - name: requests\n    reason: reviewed\n", "reviewed");
    }

    private static String repoUrl(String repo) {
        return baseUrl + "/" + ADMIN + "/" + repo + ".git";
    }

    private GitOpsProperties gitops(String repo, @Nullable String branch, @Nullable String withToken, Path cloneDir) {
        return new GitOpsProperties(true, repoUrl(repo), branch, "", "oauth2", withToken, cloneDir, 10, 30, 60);
    }

    @Test
    void aPublicRepositoryIsFetchedWithoutToken() throws IOException {
        Path clone = temp.resolve("clone");

        String commit = workingCopy.update(gitops("allowlist-public", null, null, clone));

        assertThat(commit).matches("[0-9a-f]{40}");
        assertThat(AllowlistFiles.read(clone, clone).entries()).extracting(StoredEntry::entry)
                .extracting(entry -> entry.name()).containsExactly("esbuild");
    }

    @Test
    void aLaterCommitIsPickedUpByTheNextUpdate() throws Exception {
        createRepo("allowlist-moving", false);
        putFile("allowlist-moving", "npm.yaml", ESBUILD, null);
        Path clone = temp.resolve("clone");
        GitOpsProperties moving = gitops("allowlist-moving", null, null, clone);
        String first = workingCopy.update(moving);

        putFile("allowlist-moving", "maven.yaml", "allowlist:\n  - name: \"com.acme:tool\"\n    reason: reviewed\n", null);
        String second = workingCopy.update(moving);

        assertThat(second).isNotEqualTo(first);
        assertThat(AllowlistFiles.read(clone, clone).entries()).hasSize(2);
    }

    @Test
    void aPrivateRepositoryNeedsTheToken() throws IOException {
        Path clone = temp.resolve("clone");

        workingCopy.update(gitops("allowlist-private", null, token, clone));

        assertThat(AllowlistFiles.read(clone, clone.resolve("pbg")).entries()).hasSize(1);
    }

    @Test
    void aPrivateRepositoryIsRefusedWithoutTokenOrWithAWrongOne() {
        assertThatThrownBy(() -> workingCopy.update(gitops("allowlist-private", null, null, temp.resolve("none"))))
                .isInstanceOf(IOException.class);
        assertThatThrownBy(() -> workingCopy.update(gitops("allowlist-private", null, "wrong-token-value", temp.resolve("wrong"))))
                .isInstanceOf(IOException.class)
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("wrong-token-value"));
    }

    @Test
    void theConfiguredBranchIsFetchedInsteadOfTheDefaultOne() throws IOException {
        Path clone = temp.resolve("clone");

        workingCopy.update(gitops("allowlist-private", "reviewed", token, clone));

        assertThat(AllowlistFiles.read(clone, clone.resolve("pbg")).entries()).extracting(StoredEntry::sourceFile)
                .containsExactly("npm.yaml", "pypi.yaml");
    }

    @Test
    void anUnknownBranchFailsTheUpdate() {
        assertThatThrownBy(() -> workingCopy.update(gitops("allowlist-public", "missing", null, temp.resolve("clone"))))
                .isInstanceOf(IOException.class);
    }

    private static GitWorkingCopy throughProxy(int port, String nonProxyHosts, boolean gitInScope) {
        return new GitWorkingCopy(new CorporateProxy(TestProperties.withCorporateProxy(new CorporateProxyProperties(
                true, "localhost", port, nonProxyHosts, new CorporateProxyScope(true, gitInScope, false)))));
    }

    @Test
    void aRepositoryInTheProxyScopeIsFetchedThroughIt() throws IOException {
        try (ForwardingProxy proxy = new ForwardingProxy()) {
            Path clone = temp.resolve("clone");

            throughProxy(proxy.port(), "", true).update(gitops("allowlist-private", null, token, clone));

            assertThat(AllowlistFiles.read(clone, clone.resolve("pbg")).entries()).hasSize(1);
            assertThat(proxy.requests()).isNotEmpty().allMatch(line -> line.contains(repoUrl("allowlist-private")));
        }
    }

    @Test
    void anUnreachableProxyFailsTheUpdateInsteadOfGoingDirect() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }

        assertThatThrownBy(() -> throughProxy(closedPort, "", true).update(gitops("allowlist-public", null, null, temp.resolve("c"))))
                .isInstanceOf(IOException.class);
    }

    @Test
    void outOfScopeOrNonProxyHostsAreReachedDirectly() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }

        throughProxy(closedPort, "", false).update(gitops("allowlist-public", null, null, temp.resolve("scope")));
        throughProxy(closedPort, "other.example|" + GITEA.getHost(), true)
                .update(gitops("allowlist-public", null, null, temp.resolve("bypass")));

        assertThat(temp.resolve("scope/npm.yaml")).exists();
        assertThat(temp.resolve("bypass/npm.yaml")).exists();
    }

    // ── Gitea API ────────────────────────────────────────────────────────────────

    private static void createRepo(String name, boolean isPrivate) throws Exception {
        api("POST", "/api/v1/user/repos",
                "{\"name\":\"" + name + "\",\"private\":" + isPrivate + ",\"auto_init\":true,\"default_branch\":\"main\"}");
    }

    private static void putFile(String repo, String path, String content, @Nullable String branch) throws Exception {
        String encoded = Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8));
        api("POST", "/api/v1/repos/" + ADMIN + "/" + repo + "/contents/" + path, "{\"message\":\"Add " + path
                + "\",\"content\":\"" + encoded + "\"" + (branch == null ? "" : ",\"branch\":\"" + branch + "\"") + "}");
    }

    private static String api(String method, String path, String body) throws Exception {
        String credentials = Base64.getEncoder().encodeToString((ADMIN + ":" + PASSWORD).getBytes(StandardCharsets.UTF_8));
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpResponse<String> response = client.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .header("Authorization", "Basic " + credentials)
                    .header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(body))
                    .build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw new IllegalStateException(method + " " + path + " -> " + response.statusCode() + ": " + response.body());
            }
            return response.body();
        }
    }
}
