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
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.IsolationProperties;
import com.silicaproxy.packagebehaviorguardian.service.statics.ProcessRunner;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * One private scratch directory per job, under {@code artifact.work-dir}, always deleted afterwards,
 * with the HOME of its external scanners inside ({@link ProcessRunner#home}).
 *
 * <p>With {@code scanners.isolation} (the Docker image), each live job holds one scanner group of a
 * pool, released on deletion: its directory is {@code rwxr-x---} for that group (the scanner reads
 * the artifacts but cannot write beside them), its HOME {@code rwxrwx---}, the artifacts {@code
 * rw-r-----}. scanner-exec runs the tools as uid = gid = that group: one job's scanner can neither
 * read nor alter another job's directory, nor this service's files. This service belongs to every
 * group of the pool, which lets it hand directories over (chgrp) and delete what the scanner left
 * (scanner-exec makes it group-writable before exiting).
 */
@Component
@NullMarked
public class ScratchDirectories {

    private static final Logger LOG = LoggerFactory.getLogger(ScratchDirectories.class);

    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> GROUP_READ_ONLY = PosixFilePermissions.fromString("rwxr-x---");
    private static final Set<PosixFilePermission> GROUP_WRITABLE = PosixFilePermissions.fromString("rwxrwx---");
    private static final Set<PosixFilePermission> GROUP_READABLE_FILE = PosixFilePermissions.fromString("rw-r-----");

    private final Path root;
    // Free scanner groups; null without isolation.
    private final @Nullable BlockingQueue<Integer> freeGroups;
    private final Map<Path, Integer> groupOf = new ConcurrentHashMap<>();

    public ScratchDirectories(PackageBehaviorGuardianProperties properties) {
        Path configured = properties.artifact().workDir();
        this.root = configured != null ? configured : Path.of(System.getProperty("java.io.tmpdir"));
        IsolationProperties isolation = properties.scanners().isolation();
        Integer firstGid = isolation.firstGid();
        if (firstGid == null) {
            this.freeGroups = null;
        } else {
            this.freeGroups = new ArrayBlockingQueue<>(isolation.slots());
            for (int gid = firstGid; gid < firstGid + isolation.slots(); gid++) {
                freeGroups.add(gid);
            }
        }
    }

    /** Waits for a free scanner group when every one is taken (more jobs in flight than slots). */
    public Path create() throws IOException {
        Files.createDirectories(root);
        Path directory = Files.createTempDirectory(root, "pbg-job-");
        Path home = Files.createDirectory(ProcessRunner.home(directory));
        if (freeGroups == null) {
            return directory;
        }
        int gid;
        try {
            gid = freeGroups.take();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            delete(directory);
            throw new IOException("Interrupted while waiting for a scanner group", e);
        }
        groupOf.put(directory, gid);
        try {
            handOver(directory, gid, GROUP_READ_ONLY);
            handOver(home, gid, GROUP_WRITABLE);
        } catch (IOException | RuntimeException e) {
            delete(directory);
            throw e;
        }
        return directory;
    }

    /** True when the scanners run under the job's uid (scanner-exec): then they must not overlap within a job. */
    public boolean isolated() {
        return freeGroups != null;
    }

    /**
     * The working directory, HOME and TMPDIR of one scanner process of the job, so that processes never
     * share caches or extracted files. Handed to the job's group like the job directory: scanner-exec
     * derives the uid from it and refuses a directory the scanner could write to.
     */
    public Path createScanDirectory(Path directory) throws IOException {
        Path scan = Files.createTempDirectory(directory, "scan-");
        Path home = Files.createDirectory(ProcessRunner.home(scan));
        Integer gid = groupOf.get(directory);
        if (gid != null) {
            handOver(scan, gid, GROUP_READ_ONLY);
            handOver(home, gid, GROUP_WRITABLE);
        }
        return scan;
    }

    /** Lets the job's scanner read a file this service wrote into its directory (no-op without isolation). */
    public void shareWithScanner(Path directory, Path file) throws IOException {
        Integer gid = groupOf.get(directory);
        if (gid != null) {
            handOver(file, gid, GROUP_READABLE_FILE);
        }
    }

    // Group first, then the mode: the entry is never open to a group other than the job's.
    private static void handOver(Path path, int gid, Set<PosixFilePermission> permissions) throws IOException {
        PosixFileAttributeView view = Files.getFileAttributeView(path, PosixFileAttributeView.class);
        // A numeric name is taken as the gid when no group has that name.
        GroupPrincipal group = path.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByGroupName(Integer.toString(gid));
        view.setGroup(group);
        view.setPermissions(permissions);
    }

    // Does not follow symlinks: a scanner could have left one pointing outside the directory. Tools
    // may extract read-only directories (0555 in a tarball): they are made writable before their
    // content is deleted, and a failure on one entry does not stop the rest of the cleanup. Entries a
    // scanner created under isolation belong to its uid, so their mode cannot be changed here:
    // scanner-exec has made them group-writable, which is enough to delete them.
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
        } finally {
            Integer gid = groupOf.remove(directory);
            if (gid != null && freeGroups != null) {
                freeGroups.add(gid);
            }
        }
    }
}
