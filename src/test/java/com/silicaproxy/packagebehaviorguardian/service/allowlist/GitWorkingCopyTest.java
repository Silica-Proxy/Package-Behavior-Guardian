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

import com.silicaproxy.packagebehaviorguardian.TestProperties;
import com.silicaproxy.packagebehaviorguardian.config.CorporateProxy;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.GitOpsProperties;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.revwalk.RevCommit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GitWorkingCopyTest {

    @TempDir
    Path temp;

    private final GitWorkingCopy workingCopy = new GitWorkingCopy(new CorporateProxy(TestProperties.defaults()));

    private RevCommit remoteWith(Path remote, String branch, String content) throws IOException, GitAPIException {
        try (Git git = Git.init().setDirectory(remote.toFile()).setInitialBranch(branch).call()) {
            Files.writeString(remote.resolve("npm.yaml"), content);
            git.add().addFilepattern(".").call();
            return git.commit().setMessage("init").setAuthor("t", "t@example.org").setCommitter("t", "t@example.org")
                    .setSign(false).call();
        }
    }

    private static GitOpsProperties gitops(Path remote, String branch, Path cloneDir) {
        return new GitOpsProperties(true, remote.toUri().toString(), branch, "", "oauth2", null, cloneDir, 10, 30, 60);
    }

    @Test
    void fetchesTheConfiguredBranchIntoANewWorkingCopy() throws IOException, GitAPIException {
        Path remote = temp.resolve("remote");
        RevCommit commit = remoteWith(remote, "allowlist", "allowlist: []\n");
        Path clone = temp.resolve("clone");

        assertThat(workingCopy.update(gitops(remote, "allowlist", clone))).isEqualTo(commit.name());
        assertThat(clone.resolve("npm.yaml")).hasContent("allowlist: []");
    }

    @Test
    void neverDeletesAMisconfiguredDirectory() throws IOException, GitAPIException {
        Path remote = temp.resolve("remote");
        remoteWith(remote, "main", "allowlist: []\n");
        Path notOurs = Files.createDirectories(temp.resolve("app"));
        Files.writeString(notOurs.resolve("precious.txt"), "keep me");

        assertThatThrownBy(() -> workingCopy.update(gitops(remote, "", notOurs)))
                .isInstanceOf(IOException.class).hasMessageContaining("refusing to delete it");
        assertThat(notOurs.resolve("precious.txt")).hasContent("keep me");
    }

    @Test
    void aBlankCloneDirMeansTheDefaultOne() {
        GitOpsProperties blank = new GitOpsProperties(false, null, null, "", "oauth2", null, Path.of(""), 10, 30, 60);

        assertThat(blank.effectiveCloneDir()).isEqualTo(Path.of(System.getProperty("java.io.tmpdir"), "pbg-allowlist-git"));
    }
}
