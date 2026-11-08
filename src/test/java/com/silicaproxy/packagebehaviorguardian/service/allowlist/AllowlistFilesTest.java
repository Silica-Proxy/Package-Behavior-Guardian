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

import com.silicaproxy.packagebehaviorguardian.dao.repository.AllowlistRepository.StoredEntry;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.AllowlistEntry;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AllowlistFilesTest {

    @TempDir
    Path root;

    private Path write(String relative, String content) throws IOException {
        Path file = root.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
        return file;
    }

    @Test
    void readsEveryEcosystemFromItsFileName() throws IOException {
        write("npm.yaml", """
                allowlist:
                  - name: esbuild
                    version: 0.25.0
                    rule-id: GDG-RISK
                    detail: install hooks
                    reason: downloads its platform binary
                """);
        write("pypi.yml", """
                allowlist:
                  - name: Typing_Extensions
                    reason: reviewed
                """);
        write("maven.yaml", """
                allowlist:
                  - name: "com.example:lib"
                    rule-id: JVM-005
                    reason: ships its JNI library
                """);

        AllowlistFiles.Result result = AllowlistFiles.read(root, root);

        assertThat(result.skipped()).isEmpty();
        assertThat(result.entries()).extracting(StoredEntry::entry).containsExactly(
                new AllowlistEntry("npm", "esbuild", "0.25.0", "GDG-RISK", "install hooks", "downloads its platform binary"),
                new AllowlistEntry("pypi", "typing-extensions", null, null, null, "reviewed"),
                new AllowlistEntry("maven", "com.example:lib", null, "JVM-005", null, "ships its JNI library"));
        assertThat(result.entries()).extracting(StoredEntry::sourceFile).containsExactly("npm.yaml", "pypi.yml", "maven.yaml");
    }

    @Test
    void readsTheConfiguredSubdirectoryOnly() throws IOException {
        write("npm.yaml", "allowlist:\n  - name: elsewhere\n    reason: not this directory\n");
        write("package-behavior-guardian/npm.yaml", "allowlist:\n  - name: here\n    reason: reviewed\n");

        AllowlistFiles.Result result = AllowlistFiles.read(root, root.resolve("package-behavior-guardian"));

        assertThat(result.entries()).extracting(stored -> stored.entry().name()).containsExactly("here");
    }

    @Test
    void anInvalidEntryIsSkippedAndTheOthersApply() throws IOException {
        write("npm.yaml", """
                allowlist:
                  - name: misspelt
                    rule_id: GDG-RISK
                    reason: a misspelt key would otherwise widen the entry to every rule
                  - name: no-reason
                  - reason: no name
                  - name: blank-detail
                    detail: "  "
                    reason: would match every finding
                  - name: blank-version
                    version: ""
                    reason: would never match
                  - name: kept
                    reason: reviewed
                """);

        AllowlistFiles.Result result = AllowlistFiles.read(root, root);

        assertThat(result.entries()).extracting(stored -> stored.entry().name()).containsExactly("kept");
        assertThat(result.skipped()).hasSize(5);
        assertThat(result.skipped().getFirst()).startsWith("npm.yaml entry #1: ").contains("rule_id");
    }

    @Test
    void missingAndEmptyFilesHoldNoEntry() throws IOException {
        write("npm.yaml", "");
        write("pypi.yaml", "allowlist:\n");

        AllowlistFiles.Result result = AllowlistFiles.read(root, root);

        assertThat(result.entries()).isEmpty();
        assertThat(result.skipped()).isEmpty();
    }

    @Test
    void aFileThatIsNotAnAllowlistFailsTheWholeRead() throws IOException {
        write("npm.yaml", "allowlist:\n  - name: [unclosed\n");
        assertThatThrownBy(() -> AllowlistFiles.read(root, root)).isInstanceOf(IOException.class).hasMessageContaining("npm.yaml");

        write("npm.yaml", "rules:\n  - name: esbuild\n");
        assertThatThrownBy(() -> AllowlistFiles.read(root, root)).hasMessageContaining("single 'allowlist' list");
    }

    @Test
    void twoFilesForOneEcosystemAreRefused() throws IOException {
        write("npm.yaml", "allowlist:\n");
        write("npm.yml", "allowlist:\n");

        assertThatThrownBy(() -> AllowlistFiles.read(root, root)).hasMessageContaining("keep one");
    }

    @Test
    void aMissingDirectoryIsAnError() {
        assertThatThrownBy(() -> AllowlistFiles.read(root, root.resolve("typo"))).hasMessageContaining("not found");
    }

    @Test
    void anOversizedFileIsRefused() throws IOException {
        write("npm.yaml", "allowlist:\n" + "#".repeat((int) AllowlistFiles.MAX_FILE_BYTES));

        assertThatThrownBy(() -> AllowlistFiles.read(root, root)).hasMessageContaining("larger than");
    }

    @Test
    void aLinkLeavingTheRepositoryIsRefused(@TempDir Path outside) throws IOException {
        Path secret = Files.writeString(outside.resolve("secret.yaml"), "allowlist:\n");
        Files.createSymbolicLink(root.resolve("npm.yaml"), secret);
        assertThatThrownBy(() -> AllowlistFiles.read(root, root)).hasMessageContaining("not a regular file");

        Files.delete(root.resolve("npm.yaml"));
        Files.createSymbolicLink(root.resolve("linked"), outside);
        assertThatThrownBy(() -> AllowlistFiles.read(root, root.resolve("linked"))).hasMessageContaining("leaves the repository");
    }

    @Test
    void credentialsInAnErrorMessageAreRedacted() {
        assertThat(GitOpsAllowlistSync.redact("https://user:s3cret@git.example/repo.git: not authorized"))
                .isEqualTo("https://***@git.example/repo.git: not authorized");
    }
}
