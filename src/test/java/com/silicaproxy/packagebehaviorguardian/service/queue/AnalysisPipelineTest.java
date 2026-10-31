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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.silicaproxy.packagebehaviorguardian.TestProperties;
import com.silicaproxy.packagebehaviorguardian.dao.repository.ScanCacheRepository;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.JobStatus;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.service.artifact.ArtifactDownloader;
import com.silicaproxy.packagebehaviorguardian.service.artifact.DownloadedArtifact;
import com.silicaproxy.packagebehaviorguardian.service.artifact.ReleaseArtifactResolver;
import com.silicaproxy.packagebehaviorguardian.service.statics.FileScanner;
import com.silicaproxy.packagebehaviorguardian.service.statics.HostileArtifactException;
import com.silicaproxy.packagebehaviorguardian.service.statics.ScanCache;
import com.silicaproxy.packagebehaviorguardian.service.statics.ScanContext;
import com.silicaproxy.packagebehaviorguardian.service.statics.StaticScanner;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AnalysisPipelineTest {

    private static final int FILES = 8;

    private final ReleaseArtifactResolver resolver = mock(ReleaseArtifactResolver.class);
    private final ArtifactDownloader downloader = mock(ArtifactDownloader.class);
    private final ScanCacheRepository cacheRepository = mock(ScanCacheRepository.class);
    private final AnalysisJob job = new AnalysisJob(UUID.randomUUID(), "pypi", "foo", "1.0.0",
            "https://files.pythonhosted.org/foo-1.0.0.tar.gz", JobStatus.RUNNING, 1, null, Instant.now());

    @TempDir
    private Path scratch;

    @BeforeEach
    void release() throws IOException {
        List<URI> files = IntStream.range(0, FILES)
                .mapToObj(i -> URI.create("https://files.pythonhosted.org/foo-1.0.0-" + i + ".whl"))
                .toList();
        when(resolver.resolve(job)).thenReturn(new ReleaseArtifactResolver.ReleaseArtifacts(files));
        when(downloader.download(any(URI.class), any(Path.class))).thenAnswer(invocation -> {
            Path target = invocation.getArgument(1);
            Files.writeString(target, target.getFileName().toString());
            return Optional.of(new DownloadedArtifact(invocation.getArgument(0), target,
                    "sha-" + target.getFileName(), 1));
        });
    }

    @Test
    void aParallelRunGivesTheFindingsOfASequentialOne() throws IOException {
        FakeFileScanner first = new FakeFileScanner("first", null);
        FakeFileScanner second = new FakeFileScanner("second", null);
        List<StaticScanner> scanners = List.of(first, wholeVersionScanner(), second);

        List<Finding> sequential = pipeline(scanners, 1).run(job).findings();
        List<Finding> parallel = pipeline(scanners, 4).run(job).findings();

        assertThat(parallel).hasSize(2 * FILES + 1).isEqualTo(sequential);
        assertThat(parallel.get(0).location()).startsWith("0-");
        assertThat(parallel.get(FILES).scanner()).isEqualTo("version");
        // Each process its own directory (HOME, TMPDIR): concurrent scans never share one.
        assertThat(first.workDirs).hasSize(2 * FILES);
    }

    @Test
    void aFailingFileFailsTheWholeJobWithTheSameException() {
        HostileArtifactException hostile = new HostileArtifactException("mal produced more than 64 MB of output", false);
        FakeFileScanner failing = new FakeFileScanner("failing", Map.of(5, hostile));

        assertThatThrownBy(() -> pipeline(List.of(failing), 3).run(job)).isSameAs(hostile);
        verifyNoInteractions(cacheRepository); // the cache is disabled here: nothing stored either way
    }

    private AnalysisPipeline pipeline(List<StaticScanner> scanners, int parallelism) {
        PackageBehaviorGuardianProperties defaults = TestProperties.defaults();
        PackageBehaviorGuardianProperties properties = new PackageBehaviorGuardianProperties(defaults.security(),
                defaults.intake(), new PackageBehaviorGuardianProperties.ArtifactProperties(200, 60, scratch),
                defaults.registries(), defaults.queue(), defaults.callback(), defaults.retention(),
                new PackageBehaviorGuardianProperties.AnalysisProperties("1", null, parallelism, false, 30),
                defaults.scanners(), defaults.allowlist());
        return new AnalysisPipeline(resolver, downloader, scanners, new ScratchDirectories(properties),
                new ScanCache(cacheRepository, properties), properties);
    }

    private static StaticScanner wholeVersionScanner() {
        return new StaticScanner() {
            @Override
            public String name() {
                return "version";
            }

            @Override
            public boolean enabled() {
                return true;
            }

            @Override
            public boolean supports(String ecosystem) {
                return true;
            }

            @Override
            public List<Finding> scan(ScanContext context) {
                return List.of(new Finding("VER-001", Severity.LOW, "version", context.artifacts().size() + " files", null));
            }
        };
    }

    /** One finding per file; files finish in reverse order of submission, and some may fail. */
    private static final class FakeFileScanner implements FileScanner {

        private final String name;
        private final Map<Integer, IOException> failures;
        private final Set<Path> workDirs = ConcurrentHashMap.newKeySet();

        FakeFileScanner(String name, Map<Integer, IOException> failures) {
            this.name = name;
            this.failures = failures == null ? Map.of() : failures;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public boolean enabled() {
            return true;
        }

        @Override
        public boolean supports(String ecosystem) {
            return true;
        }

        @Override
        public String cacheKey(String ecosystem) {
            return name;
        }

        @Override
        public List<Finding> scanFile(String ecosystem, Path artifact, Path workDir) throws IOException {
            workDirs.add(workDir);
            String file = String.valueOf(artifact.getFileName());
            int index = Integer.parseInt(file.substring(0, file.indexOf('-')));
            try {
                Thread.sleep(5L * (FILES - index));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            }
            IOException failure = failures.get(index);
            if (failure != null) {
                throw failure;
            }
            List<Finding> findings = new ArrayList<>();
            findings.add(new Finding("FAKE-" + name, Severity.LOW, name, "seen " + Files.readString(artifact), file));
            return findings;
        }
    }
}
