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


package com.silicaproxy.packagebehaviorguardian.service.queue;

import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** One private scratch directory per job, under {@code artifact.work-dir}, always deleted afterwards. */
@Component
@NullMarked
public class ScratchDirectories {

    private static final Logger LOG = LoggerFactory.getLogger(ScratchDirectories.class);

    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rwx------");

    private final Path root;

    public ScratchDirectories(PackageBehaviorGuardianProperties properties) {
        Path configured = properties.artifact().workDir();
        this.root = configured != null ? configured : Path.of(System.getProperty("java.io.tmpdir"));
    }

    public Path create() throws IOException {
        Files.createDirectories(root);
        return Files.createTempDirectory(root, "pbg-job-");
    }

    // Does not follow symlinks: a scanner could have left one pointing outside the directory. Tools
    // may extract read-only directories (0555 in a tarball): they are made writable before their
    // content is deleted, and a failure on one entry does not stop the rest of the cleanup.
    public void delete(Path directory) {
        try {
            Files.walkFileTree(directory, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attributes) {
                    try {
                        Files.setPosixFilePermissions(dir, OWNER_ONLY);
                    } catch (IOException | UnsupportedOperationException e) {
                        // best effort: the deletion below reports what could not be removed
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                    Files.deleteIfExists(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exception) {
                    LOG.warn("Could not delete {}: {}", file, exception.getMessage());
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exception) throws IOException {
                    Files.deleteIfExists(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            LOG.warn("Could not delete scratch directory {}: {}", directory, e.getMessage());
        }
    }
}
