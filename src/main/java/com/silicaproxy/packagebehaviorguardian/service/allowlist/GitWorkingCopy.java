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

import com.silicaproxy.packagebehaviorguardian.config.CorporateProxy;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.GitOpsProperties;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.stream.Stream;
import org.eclipse.jgit.api.FetchCommand;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.ResetCommand;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.Ref;
import org.eclipse.jgit.lib.RepositoryCache;
import org.eclipse.jgit.transport.RefSpec;
import org.eclipse.jgit.transport.TransportHttp;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.eclipse.jgit.transport.http.HttpConnectionFactory;
import org.eclipse.jgit.util.FS;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

/**
 * The local working copy of the GitOps repository. Each update fetches the last commit of the branch
 * (depth 1, from the configured URL -- no remote is stored, so a changed URL is simply followed) and
 * resets the working tree to it: a force-pushed branch, or a file left over by an interrupted update,
 * never blocks the next one. HTTP(S) goes through the corporate proxy when the Git repository is in
 * its scope, set on this fetch's transport only (JGit's connection factory is global otherwise).
 */
@Component
@NullMarked
public class GitWorkingCopy {

    static final String FETCHED_REF = "refs/pbg/allowlist";
    // Inactivity timeout of the transfer, not a limit on its whole duration.
    private static final int IO_TIMEOUT_SECONDS = 60;

    private final HttpConnectionFactory connections;

    public GitWorkingCopy(CorporateProxy corporateProxy) {
        this.connections = new RoutedGitConnections(corporateProxy.gitRepository());
    }

    /** Brings the working copy to the last commit of the configured branch; returns that commit. */
    public String update(GitOpsProperties gitops) throws IOException {
        Path directory = gitops.effectiveCloneDir();
        try {
            if (!RepositoryCache.FileKey.isGitRepository(directory.resolve(Constants.DOT_GIT).toFile(), FS.DETECTED)) {
                if (Files.exists(directory)) {
                    requireOnlyAnUnfinishedRepository(directory);
                    deleteRecursively(directory);
                }
                Path parent = directory.toAbsolutePath().getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
                Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                Git.init().setDirectory(directory.toFile()).call().close();
            }
            try (Git git = Git.open(directory.toFile())) {
                String branch = gitops.branch();
                String source = branch == null || branch.isBlank() ? Constants.HEAD : Constants.R_HEADS + branch.strip();
                FetchCommand fetch = git.fetch()
                        .setRemote(gitops.repositoryUrl())
                        .setRefSpecs(new RefSpec("+" + source + ":" + FETCHED_REF))
                        .setDepth(1)
                        .setTimeout(IO_TIMEOUT_SECONDS)
                        .setTransportConfigCallback(transport -> {
                            if (transport instanceof TransportHttp http) {
                                http.setHttpConnectionFactory(connections);
                            }
                        });
                String token = gitops.token();
                if (token != null && !token.isBlank()) {
                    fetch.setCredentialsProvider(new UsernamePasswordCredentialsProvider(gitops.username(), token));
                }
                fetch.call();
                Ref fetched = git.getRepository().exactRef(FETCHED_REF);
                if (fetched == null || fetched.getObjectId() == null) {
                    throw new IOException("The fetch of " + source + " stored no commit");
                }
                ObjectId commit = fetched.getObjectId();
                git.reset().setMode(ResetCommand.ResetType.HARD).setRef(commit.name()).call();
                git.clean().setCleanDirectories(true).setForce(true).call();
                return commit.name();
            }
        } catch (GitAPIException e) {
            throw new IOException("Git synchronization of the allowlist repository failed: " + e.getMessage(), e);
        }
    }

    // A misconfigured clone-dir (the application directory, a home) must never be wiped: only an empty
    // directory, or one holding nothing but the .git of an interrupted first update, is replaced.
    private static void requireOnlyAnUnfinishedRepository(Path directory) throws IOException {
        try (Stream<Path> children = Files.list(directory)) {
            if (children.anyMatch(child -> !Constants.DOT_GIT.equals(String.valueOf(child.getFileName())))) {
                throw new IOException("gitops.clone-dir " + directory + " is not a Git working copy and is not empty:"
                        + " refusing to delete it, point clone-dir to a directory of its own");
            }
        }
    }

    // Symbolic links are deleted, never followed.
    private static void deleteRecursively(Path directory) throws IOException {
        Files.walkFileTree(directory, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, @Nullable IOException failure) throws IOException {
                if (failure != null) {
                    throw failure;
                }
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }
}
