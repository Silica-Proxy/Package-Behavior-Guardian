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

import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.ArtifactInfo;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import com.silicaproxy.packagebehaviorguardian.service.artifact.ArtifactDownloader;
import com.silicaproxy.packagebehaviorguardian.service.artifact.DownloadedArtifact;
import com.silicaproxy.packagebehaviorguardian.service.artifact.ReleaseArtifactResolver;
import com.silicaproxy.packagebehaviorguardian.service.artifact.ReleaseArtifactResolver.ReleaseArtifacts;
import com.silicaproxy.packagebehaviorguardian.service.statics.HostileArtifactException;
import com.silicaproxy.packagebehaviorguardian.service.statics.ScanContext;
import com.silicaproxy.packagebehaviorguardian.service.statics.StaticScanner;
import com.silicaproxy.packagebehaviorguardian.service.statics.Texts;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

/**
 * The static pass for one job: resolve every file of the version, download them into a scratch
 * directory, then run each enabled scanner that supports the ecosystem. Nothing from the package
 * is executed.
 */
@Component
@NullMarked
public class AnalysisPipeline {

    // Disk budget of one job, whatever its number of files (a PyPI version can ship 60 wheels).
    private static final long MAX_TOTAL_BYTES = 1024L * 1024 * 1024;

    private final ReleaseArtifactResolver resolver;
    private final ArtifactDownloader downloader;
    private final List<StaticScanner> scanners;
    private final ScratchDirectories scratchDirectories;

    public AnalysisPipeline(ReleaseArtifactResolver resolver, ArtifactDownloader downloader, List<StaticScanner> scanners,
            ScratchDirectories scratchDirectories) {
        this.resolver = resolver;
        this.downloader = downloader;
        this.scanners = List.copyOf(scanners);
        this.scratchDirectories = scratchDirectories;
    }

    public record Outcome(List<ArtifactInfo> artifacts, List<Finding> findings) {

        // The package prevents its own analysis (see HostileArtifactException): BLOCKED, not fail-open.
        static final String ANALYSIS_IMPOSSIBLE_RULE = "PBG-001";

        public Outcome {
            artifacts = List.copyOf(artifacts);
            findings = List.copyOf(findings);
        }

        static Outcome analysisImpossible(HostileArtifactException cause) {
            return new Outcome(List.of(), List.of(new Finding(ANALYSIS_IMPOSSIBLE_RULE, Severity.CRITICAL, "pipeline",
                    Texts.clip("Analysis impossible: " + cause.getMessage()), null)));
        }
    }

    public Outcome run(AnalysisJob job) throws IOException {
        Path workDir = scratchDirectories.create();
        try {
            List<DownloadedArtifact> downloaded = download(downloader, resolver.resolve(job), workDir);
            List<Finding> findings = new ArrayList<>();
            if (!downloaded.isEmpty()) {
                ScanContext context = new ScanContext(job.ecosystem(), job.name(), job.version(),
                        downloaded.stream().map(DownloadedArtifact::path).toList(), workDir);
                for (StaticScanner scanner : scanners) {
                    if (scanner.enabled() && scanner.supports(job.ecosystem())) {
                        findings.addAll(scanner.scan(context));
                    }
                }
            }
            List<ArtifactInfo> artifacts = downloaded.stream()
                    .map(artifact -> new ArtifactInfo(artifact.url().toString(), artifact.sha256(), artifact.sizeBytes()))
                    .toList();
            return new Outcome(artifacts, findings);
        } finally {
            scratchDirectories.delete(workDir);
        }
    }

    private static List<DownloadedArtifact> download(ArtifactDownloader downloader, ReleaseArtifacts release, Path workDir)
            throws IOException {
        List<DownloadedArtifact> downloaded = new ArrayList<>();
        long total = 0;
        int index = 0;
        for (URI url : release.files()) {
            DownloadedArtifact artifact = downloader.download(url, workDir.resolve(index++ + "-" + fileName(url)))
                    .orElseThrow(() -> new IOException("Not found: " + url));
            downloaded.add(artifact);
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
