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

import com.silicaproxy.packagebehaviorguardian.BaseIntegrationTest;
import com.silicaproxy.packagebehaviorguardian.model.dto.Verdict;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import com.silicaproxy.packagebehaviorguardian.service.monitoring.MonitoringService;
import com.silicaproxy.packagebehaviorguardian.service.verdict.VerdictPolicy;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.FileSystemUtils;

/**
 * The GitOps allowlist end to end: a local Git repository, the synchronization into the database, the
 * reload by the store and the verdict that follows -- an added entry allows, a removed one blocks again,
 * a broken commit keeps the entries in force.
 */
class GitOpsAllowlistIntegrationTest extends BaseIntegrationTest {

    private static final Path REMOTE;
    private static final Path CLONE;
    private static final Finding EXEC = new Finding("JVM-001", Severity.CRITICAL, "bytecode",
            "Process execution in a static initializer", "com/acme/Init.class");

    static {
        try {
            REMOTE = Files.createTempDirectory("pbg-gitops-remote");
            CLONE = Files.createTempDirectory("pbg-gitops-clone").resolve("copy");
            try (Git git = Git.init().setDirectory(REMOTE.toFile()).setInitialBranch("main").call()) {
                commit(git, "maven.yaml", "allowlist:\n");
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (GitAPIException e) {
            throw new IllegalStateException(e);
        }
    }

    @Autowired
    private GitOpsAllowlistSync sync;

    @Autowired
    private AllowlistStore store;

    @Autowired
    private VerdictPolicy verdictPolicy;

    @Autowired
    private MonitoringService monitoringService;

    @DynamicPropertySource
    static void gitops(DynamicPropertyRegistry registry) {
        registry.add("packagebehaviorguardian.gitops.enabled", () -> "true");
        registry.add("packagebehaviorguardian.gitops.repository-url", () -> REMOTE.toUri().toString());
        registry.add("packagebehaviorguardian.gitops.path", () -> "pbg");
        registry.add("packagebehaviorguardian.gitops.clone-dir", CLONE::toString);
        // Synchronized by the test only.
        registry.add("packagebehaviorguardian.gitops.initial-delay-ms", () -> "3600000");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        FileSystemUtils.deleteRecursively(REMOTE);
        FileSystemUtils.deleteRecursively(CLONE.getParent());
    }

    @BeforeEach
    void resetRepository() throws IOException, GitAPIException {
        try (Git git = Git.open(REMOTE.toFile())) {
            commit(git, "pbg/maven.yaml", "allowlist:\n");
        }
        assertThat(sync.sync()).isTrue();
    }

    private static void commit(Git git, String file, String content) throws IOException, GitAPIException {
        Path path = REMOTE.resolve(file);
        Files.createDirectories(path.getParent());
        Files.writeString(path, content);
        git.add().addFilepattern(".").call();
        git.commit().setMessage("update " + file).setAuthor("test", "test@example.org")
                .setCommitter("test", "test@example.org").setSign(false).call();
    }

    private Verdict verdict() {
        return verdictPolicy.decide("maven", "com.acme:tool", "2.0", List.of(EXEC)).verdict();
    }

    @Test
    void anEntryMergedInTheRepositoryAllowsAndItsRemovalBlocksAgain() throws IOException, GitAPIException {
        assertThat(verdict()).isEqualTo(Verdict.BLOCKED);

        try (Git git = Git.open(REMOTE.toFile())) {
            commit(git, "pbg/maven.yaml", """
                    allowlist:
                      - name: "com.acme:tool"
                        rule-id: JVM-001
                        reason: probes the OS at load time, reviewed
                    """);
        }
        assertThat(sync.sync()).isTrue();
        assertThat(verdict()).isEqualTo(Verdict.ALLOWED);
        assertThat(monitoringService.gitopsHealth().status()).isEqualTo("UP");

        try (Git git = Git.open(REMOTE.toFile())) {
            commit(git, "pbg/maven.yaml", "allowlist:\n");
        }
        assertThat(sync.sync()).isTrue();
        assertThat(verdict()).isEqualTo(Verdict.BLOCKED);
    }

    @Test
    void aBrokenCommitKeepsTheEntriesInForceAndDegradesTheHealth() throws IOException, GitAPIException {
        try (Git git = Git.open(REMOTE.toFile())) {
            commit(git, "pbg/maven.yaml", "allowlist:\n  - name: \"com.acme:tool\"\n    reason: reviewed\n");
        }
        assertThat(sync.sync()).isTrue();
        long generation = store.state().generation();

        try (Git git = Git.open(REMOTE.toFile())) {
            commit(git, "pbg/maven.yaml", "allowlist:\n  - name: [unclosed\n");
        }
        assertThat(sync.sync()).isFalse();

        store.refresh();
        assertThat(store.state().generation()).isEqualTo(generation);
        assertThat(verdict()).isEqualTo(Verdict.ALLOWED);
        MonitoringService.ComponentHealth health = monitoringService.gitopsHealth();
        assertThat(health.status()).isEqualTo("DEGRADED");
        assertThat(String.valueOf(health.details().get("lastError"))).contains("maven.yaml is not valid YAML");
    }

    @Test
    void aSkippedEntryDegradesTheHealthButTheOthersApply() throws IOException, GitAPIException {
        try (Git git = Git.open(REMOTE.toFile())) {
            commit(git, "pbg/maven.yaml", """
                    allowlist:
                      - name: "com.acme:tool"
                        rule_id: JVM-001
                        reason: misspelt key
                      - name: "com.acme:other"
                        reason: reviewed
                    """);
        }
        assertThat(sync.sync()).isTrue();

        assertThat(verdict()).isEqualTo(Verdict.BLOCKED);
        assertThat(store.entries()).anyMatch(entry -> "com.acme:other".equals(entry.name()));
        assertThat(monitoringService.gitopsHealth().status()).isEqualTo("DEGRADED");
        assertThat(monitoringService.gitopsHealth().details()).containsEntry("skipped", 1);
    }

    @Test
    void anUnchangedRepositoryDoesNotBumpTheGeneration() throws IOException, GitAPIException {
        long generation = store.state().generation();
        try (Git git = Git.open(REMOTE.toFile())) {
            commit(git, "README.md", "a commit outside the allowlist files");
        }

        assertThat(sync.sync()).isTrue();
        store.refresh();

        assertThat(store.state().generation()).isEqualTo(generation);
        assertThat(store.state().lastError()).isNull();
        assertThat(monitoringService.gitopsHealth().status()).isEqualTo("UP");
    }

    @Test
    void anEntryIsDescribedForTheLogs() {
        assertThat(AllowlistStore.describe(new com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties
                .AllowlistEntry("npm", "esbuild", null, "GDG-RISK", "install hooks", "reviewed")))
                .isEqualTo("npm/esbuild@* rule=GDG-RISK detail=\"install hooks\" reason=\"reviewed\"");
    }

    @Test
    void aRewrittenHistoryIsFollowed() throws IOException, GitAPIException {
        try (Git git = Git.open(REMOTE.toFile())) {
            commit(git, "pbg/maven.yaml", "allowlist:\n  - name: \"com.acme:tool\"\n    reason: reviewed\n");
            assertThat(sync.sync()).isTrue();
            // Force-push equivalent: the branch now points to a commit the working copy never had as a descendant.
            git.reset().setMode(org.eclipse.jgit.api.ResetCommand.ResetType.HARD).setRef("HEAD~2").call();
            commit(git, "pbg/maven.yaml", "allowlist:\n");
        }

        assertThat(sync.sync()).isTrue();
        assertThat(verdict()).isEqualTo(Verdict.BLOCKED);
    }
}
