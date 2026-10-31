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

import static org.assertj.core.api.Assertions.assertThat;

import com.silicaproxy.packagebehaviorguardian.TestProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.ArtifactProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.IsolationProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.ScannerProperties;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

// The switch to the scanner's uid itself (docker/scanner-exec.c) needs the image's users and file
// capabilities: it is only exercised in the container. Here the "scanner group" is the test user's own.
@DisabledOnOs(OS.WINDOWS)
class ScratchDirectoriesTest {

    @TempDir
    Path root;

    private ScratchDirectories scratchDirectories(@Nullable Integer firstGid, int slots) {
        PackageBehaviorGuardianProperties defaults = TestProperties.defaults();
        ScannerProperties scanners = defaults.scanners();
        return new ScratchDirectories(new PackageBehaviorGuardianProperties(defaults.security(), defaults.intake(),
                new ArtifactProperties(200, 60, root), defaults.registries(), defaults.queue(), defaults.callback(), defaults.retention(),
                defaults.analysis(),
                new ScannerProperties(scanners.guarddog(), scanners.malcontent(), scanners.bytecode(),
                        new IsolationProperties(firstGid, slots)),
                defaults.allowlist()));
    }

    private int ownGid() throws IOException {
        return (Integer) Files.getAttribute(Files.createTempFile(root, "probe", ""), "unix:gid");
    }

    private static String mode(Path path) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(path));
    }

    @Test
    void withoutIsolationTheDirectoryIsPrivate() throws IOException {
        ScratchDirectories directories = scratchDirectories(null, 64);

        Path job = directories.create();
        Path artifact = Files.writeString(job.resolve("0-foo.tgz"), "x");
        directories.shareWithScanner(job, artifact);

        assertThat(mode(job)).isEqualTo("rwx------");
        assertThat(job.resolve("home")).isDirectory();
        directories.delete(job);
        assertThat(job).doesNotExist();
    }

    @Test
    void withIsolationTheJobIsHandedToItsScannerGroup() throws IOException {
        int gid = ownGid();
        ScratchDirectories directories = scratchDirectories(gid, 1);

        Path job = directories.create();
        Path artifact = Files.writeString(job.resolve("0-foo.tgz"), "x");
        directories.shareWithScanner(job, artifact);

        // The scanner reads the job's directory and artifacts, writes only to its HOME; others get nothing.
        assertThat(Files.getAttribute(job, "unix:gid")).isEqualTo(gid);
        assertThat(mode(job)).isEqualTo("rwxr-x---");
        assertThat(Files.getAttribute(job.resolve("home"), "unix:gid")).isEqualTo(gid);
        assertThat(mode(job.resolve("home"))).isEqualTo("rwxrwx---");
        assertThat(Files.getAttribute(artifact, "unix:gid")).isEqualTo(gid);
        assertThat(mode(artifact)).isEqualTo("rw-r-----");
        directories.delete(job);
        assertThat(job).doesNotExist();
    }

    @Test
    void aScannerGroupServesOneJobAtATime() throws Exception {
        ScratchDirectories directories = scratchDirectories(ownGid(), 1);
        Path first = directories.create();

        CompletableFuture<Path> second = CompletableFuture.supplyAsync(() -> {
            try {
                return directories.create();
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        });
        Thread.sleep(300);
        assertThat(second).isNotDone();

        directories.delete(first);
        Path next = second.get(5, TimeUnit.SECONDS);
        assertThat(next).isDirectory().isNotEqualTo(first);
        directories.delete(next);
    }

    @Test
    void readOnlyDirectoriesLeftByAToolAreDeleted() throws IOException {
        ScratchDirectories directories = scratchDirectories(ownGid(), 1);
        Path job = directories.create();
        Path extracted = Files.createDirectories(job.resolve("home/package/lib"));
        Files.writeString(extracted.resolve("index.js"), "x");
        Files.setPosixFilePermissions(extracted, PosixFilePermissions.fromString("r-xr-xr-x"));
        Files.setPosixFilePermissions(extracted.getParent(), PosixFilePermissions.fromString("r-xr-xr-x"));

        directories.delete(job);

        assertThat(job).doesNotExist();
    }
}
