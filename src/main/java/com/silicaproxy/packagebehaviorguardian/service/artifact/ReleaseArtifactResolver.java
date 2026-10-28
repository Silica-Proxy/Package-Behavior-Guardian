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


package com.silicaproxy.packagebehaviorguardian.service.artifact;

import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.service.intake.UrlPolicy;
import com.silicaproxy.packagebehaviorguardian.service.statics.HostileArtifactException;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

/**
 * Which files make up a version. SilicaProxy caches one verdict per (package, version), whatever
 * file was requested first, so the analysis must cover the whole version, not just that file:
 * <ul>
 *   <li>npm: the single tarball (the request URL);</li>
 *   <li>PyPI: every file listed by the JSON API (sdist and all wheels, yanked ones included) --
 *       otherwise a clean wheel asked first would vouch for a malicious sdist;</li>
 *   <li>Maven: the main artifact declared by the POM's packaging (none for {@code pom}), plus the
 *       requested file when it is another archive (a classifier jar, for instance).</li>
 * </ul>
 * Every file must exist: a missing one fails the job rather than being skipped. Every derived URL
 * goes through {@link UrlPolicy}.
 */
@Component
@NullMarked
public class ReleaseArtifactResolver {

    private static final List<String> ARCHIVES = List.of(".jar", ".war", ".ear", ".aar", ".rar", ".zip");

    private final RegistryClient registryClient;
    private final ArtifactDownloader downloader;
    private final UrlPolicy urlPolicy;
    private final int maxFilesPerVersion;

    public ReleaseArtifactResolver(RegistryClient registryClient, ArtifactDownloader downloader, UrlPolicy urlPolicy,
            PackageBehaviorGuardianProperties properties) {
        this.registryClient = registryClient;
        this.downloader = downloader;
        this.urlPolicy = urlPolicy;
        this.maxFilesPerVersion = properties.artifact().maxFilesPerVersion();
    }

    public record ReleaseArtifacts(List<URI> files) {

        public ReleaseArtifacts {
            files = List.copyOf(files);
        }
    }

    public ReleaseArtifacts resolve(AnalysisJob job) throws IOException {
        URI requested = urlPolicy.requireArtifactUrl(job.artifactUrl());
        return switch (job.ecosystem()) {
            case "npm" -> new ReleaseArtifacts(List.of(requested));
            case "pypi" -> pypi(job, requested);
            case "maven" -> maven(job, requested);
            default -> throw new IllegalArgumentException("Unsupported ecosystem " + job.ecosystem());
        };
    }

    private ReleaseArtifacts pypi(AnalysisJob job, URI requested) throws IOException {
        List<String> files = registryClient.pypiVersionFiles(job.name(), job.version());
        if (files.isEmpty()) {
            return new ReleaseArtifacts(List.of(requested));
        }
        if (files.size() > maxFilesPerVersion) {
            throw new HostileArtifactException("PyPI version has " + files.size() + " files (limit " + maxFilesPerVersion + ")", false);
        }
        return new ReleaseArtifacts(files.stream().map(urlPolicy::requireArtifactUrl).toList());
    }

    private ReleaseArtifacts maven(AnalysisJob job, URI requested) throws IOException {
        MavenLayout.Coordinates coordinates = MavenLayout.Coordinates.parse(job.name());
        URI pom = urlPolicy.requireArtifactUrl(MavenLayout.file(requested, coordinates, job.version(), "pom").toString());
        Optional<String> extension = MavenLayout.mainArtifactExtension(new String(downloader.fetchMetadata(pom), StandardCharsets.UTF_8));
        List<URI> files = new ArrayList<>();
        if (extension.isPresent()) {
            files.add(urlPolicy.requireArtifactUrl(MavenLayout.file(requested, coordinates, job.version(), extension.get()).toString()));
        }
        String path = requested.getPath() == null ? "" : requested.getPath().toLowerCase(Locale.ROOT);
        if (ARCHIVES.stream().anyMatch(path::endsWith) && !files.contains(requested)) {
            files.add(requested);
        }
        return new ReleaseArtifacts(files);
    }
}
