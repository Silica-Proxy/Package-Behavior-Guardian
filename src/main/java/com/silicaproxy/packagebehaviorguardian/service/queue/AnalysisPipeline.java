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

import com.silicaproxy.packagebehaviorguardian.config.LogSanitizer;
import com.silicaproxy.packagebehaviorguardian.config.Metrics;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.ArtifactInfo;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.service.artifact.ArtifactDownloader;
import com.silicaproxy.packagebehaviorguardian.service.artifact.DownloadedArtifact;
import com.silicaproxy.packagebehaviorguardian.service.artifact.ReleaseArtifactResolver;
import com.silicaproxy.packagebehaviorguardian.service.artifact.ReleaseArtifactResolver.ReleaseArtifacts;
import com.silicaproxy.packagebehaviorguardian.service.statics.FileScanner;
import com.silicaproxy.packagebehaviorguardian.service.statics.HostileArtifactException;
import com.silicaproxy.packagebehaviorguardian.service.statics.ScanCache;
import com.silicaproxy.packagebehaviorguardian.service.statics.ScanContext;
import com.silicaproxy.packagebehaviorguardian.service.statics.StaticScanner;
import com.silicaproxy.packagebehaviorguardian.service.statics.Texts;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * The static pass for one job: resolve every file of the version, download them into a scratch
 * directory, then run each enabled scanner that supports the ecosystem. Nothing from the package
 * is executed. A {@link FileScanner} runs once per file, through the {@link ScanCache}, and these
 * scans run {@code analysis.scan-parallelism} at a time (see {@link ParallelScans}).
 */
@Component
@NullMarked
public class AnalysisPipeline {

    private static final Logger LOG = LoggerFactory.getLogger(AnalysisPipeline.class);

    // Disk budget of one job, whatever its number of files (a PyPI version can ship 60 wheels).
    private static final long MAX_TOTAL_BYTES = 1024L * 1024 * 1024;

    private final ReleaseArtifactResolver resolver;
    private final ArtifactDownloader downloader;
    private final List<StaticScanner> scanners;
    private final ScratchDirectories scratchDirectories;
    private final ScanCache scanCache;
    private final int scanParallelism;
    private final AnalysisMetrics metrics;

    public AnalysisPipeline(ReleaseArtifactResolver resolver, ArtifactDownloader downloader, List<StaticScanner> scanners,
            ScratchDirectories scratchDirectories, ScanCache scanCache, PackageBehaviorGuardianProperties properties,
            AnalysisMetrics metrics) {
        this.metrics = metrics;
        this.resolver = resolver;
        this.downloader = downloader;
        this.scanners = List.copyOf(scanners);
        this.scratchDirectories = scratchDirectories;
        this.scanCache = scanCache;
        this.scanParallelism = Math.max(1, properties.analysis().scanParallelism());
    }

    /** Durations of the pipeline stages, in milliseconds; null when the stage did not run to its end. */
    public record StageTimings(@Nullable Long resolveMs, @Nullable Long downloadMs, @Nullable Long scanMs) {

        public static final StageTimings UNKNOWN = new StageTimings(null, null, null);
    }

    public record Outcome(List<ArtifactInfo> artifacts, List<Finding> findings, StageTimings timings) {

        // The package prevents its own analysis (see HostileArtifactException): BLOCKED, not fail-open.
        static final String ANALYSIS_IMPOSSIBLE_RULE = "PBG-001";

        public Outcome {
            artifacts = List.copyOf(artifacts);
            findings = List.copyOf(findings);
        }

        static Outcome analysisImpossible(HostileArtifactException cause) {
            return new Outcome(List.of(), List.of(new Finding(ANALYSIS_IMPOSSIBLE_RULE, Severity.CRITICAL, "pipeline",
                    Texts.clip("Analysis impossible: " + cause.getMessage()), null)), StageTimings.UNKNOWN);
        }
    }

    public Outcome run(AnalysisJob job) throws IOException {
        Path workDir = scratchDirectories.create();
        try {
            Instant start = Instant.now();
            ReleaseArtifacts release = resolver.resolve(job);
            Duration resolveTime = stage(job, Metrics.STAGE_RESOLVE, start);
            start = Instant.now();
            List<DownloadedArtifact> downloaded = download(release, workDir);
            Duration downloadTime = stage(job, Metrics.STAGE_DOWNLOAD, start);
            metrics.artifactBytes(job.ecosystem(), downloaded.stream().mapToLong(DownloadedArtifact::sizeBytes).sum());
            start = Instant.now();
            List<Finding> findings = downloaded.isEmpty() ? List.of() : scan(job, downloaded, workDir);
            Duration scanTime = stage(job, Metrics.STAGE_SCAN, start);
            LOG.info("Timings of {}/{}@{}: resolve {} ms, download {} ms ({} file(s)), scan {} ms", job.ecosystem(),
                    LogSanitizer.sanitize(job.name()), LogSanitizer.sanitize(job.version()), resolveTime.toMillis(),
                    downloadTime.toMillis(), downloaded.size(), scanTime.toMillis());
            List<ArtifactInfo> artifacts = downloaded.stream()
                    .map(artifact -> new ArtifactInfo(artifact.url().toString(), artifact.sha256(), artifact.sizeBytes()))
                    .toList();
            return new Outcome(artifacts, findings,
                    new StageTimings(resolveTime.toMillis(), downloadTime.toMillis(), scanTime.toMillis()));
        } finally {
            scratchDirectories.delete(workDir);
        }
    }

    private Duration stage(AnalysisJob job, String stage, Instant start) {
        Duration elapsed = Duration.between(start, Instant.now());
        metrics.stage(job.ecosystem(), stage, elapsed);
        return elapsed;
    }

    private List<Finding> timed(AnalysisJob job, StaticScanner scanner, ParallelScans.Scan<List<Finding>> scan)
            throws IOException {
        Instant start = Instant.now();
        try {
            return scan.run();
        } finally {
            metrics.scan(job.ecosystem(), scanner.name(), Duration.between(start, Instant.now()));
        }
    }

    // One task per (file scanner, file), one per other scanner, in scanner order: the findings come
    // out in the same order as a sequential run.
    private List<Finding> scan(AnalysisJob job, List<DownloadedArtifact> downloaded, Path workDir) throws IOException {
        ScanContext context = new ScanContext(job.ecosystem(), job.name(), job.version(),
                downloaded.stream().map(DownloadedArtifact::path).toList(), workDir);
        List<ParallelScans.Scan<List<Finding>>> scans = new ArrayList<>();
        for (StaticScanner scanner : scanners) {
            if (!scanner.enabled() || !scanner.supports(job.ecosystem())) {
                continue;
            }
            if (scanner instanceof FileScanner fileScanner) {
                for (DownloadedArtifact artifact : downloaded) {
                    scans.add(() -> timed(job, scanner, () -> scanCache.scan(fileScanner, job.ecosystem(), artifact.path(),
                            artifact.sha256(), scratchDirectories.createScanDirectory(workDir))));
                }
            } else {
                scans.add(() -> timed(job, scanner, () -> scanner.scan(context)));
            }
        }
        List<Finding> findings = new ArrayList<>();
        // Under scanner isolation every process of a job runs as the job's uid, and scanner-exec kills
        // all of that uid's processes when one starts and ends: the job's scans must not overlap.
        int parallelism = scratchDirectories.isolated() ? 1 : scanParallelism;
        ParallelScans.runAll(scans, parallelism).forEach(findings::addAll);
        return findings;
    }

    private List<DownloadedArtifact> download(ReleaseArtifacts release, Path workDir) throws IOException {
        List<DownloadedArtifact> downloaded = new ArrayList<>();
        long total = 0;
        int index = 0;
        for (URI url : release.files()) {
            DownloadedArtifact artifact = downloader.download(url, workDir.resolve(index++ + "-" + fileName(url)))
                    .orElseThrow(() -> new IOException("Not found: " + url));
            downloaded.add(artifact);
            scratchDirectories.shareWithScanner(workDir, artifact.path());
            total += artifact.sizeBytes();
            if (total > MAX_TOTAL_BYTES) {
                throw new HostileArtifactException("Version larger than " + MAX_TOTAL_BYTES / (1024 * 1024) + " MB in total", false);
            }
        }
        return downloaded;
    }

    // Only the last path segment, reduced to safe characters: it becomes a local file name, and its
    // extension (.tgz, .whl, .tar.gz, .jar) tells the scanners how to open it.
    private static String fileName(URI url) {
        String path = url.getPath() == null ? "" : url.getPath();
        String last = path.substring(path.lastIndexOf('/') + 1).replaceAll("[^A-Za-z0-9._-]", "_");
        if (last.isEmpty() || last.startsWith(".")) {
            last = "artifact" + last;
        }
        return last.length() > 120 ? last.substring(last.length() - 120) : last;
    }
}
