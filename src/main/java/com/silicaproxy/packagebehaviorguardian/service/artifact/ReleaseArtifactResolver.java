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
 *   <li>npm: the single tarball (the request URL, which must be the tarball of that version);</li>
 *   <li>PyPI: every file listed by the JSON API (sdist and all wheels, yanked ones included) --
 *       otherwise a clean wheel asked first would vouch for a malicious sdist. That API is the one
 *       of {@code registries.pypi-url}, so the requested file must come from that index (its own
 *       host or one of {@code registries.pypi-file-hosts}): the list of another index's package of
 *       the same name (a private index, a mirror under another name) would analyze other files
 *       than the ones installed -- dependency confusion in the verdict. The JSON API base is not
 *       derived from the artifact host: PyPI serves files and API from different hosts
 *       ({@code files.pythonhosted.org} / {@code pypi.org}), and mirrors put the API under paths
 *       of their own;</li>
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
    private final List<String> pypiHosts;

    public ReleaseArtifactResolver(RegistryClient registryClient, ArtifactDownloader downloader, UrlPolicy urlPolicy,
            PackageBehaviorGuardianProperties properties) {
        this.registryClient = registryClient;
        this.downloader = downloader;
        this.urlPolicy = urlPolicy;
        this.maxFilesPerVersion = properties.artifact().maxFilesPerVersion();
        List<String> hosts = new ArrayList<>(properties.registries().pypiFileHosts());
        hosts.add(UrlPolicy.authorityOf(URI.create(properties.registries().pypiUrl())));
        this.pypiHosts = List.copyOf(hosts);
    }

    /**
     * Rejects a PyPI artifact URL that the JSON API of {@code registries.pypi-url} does not describe;
     * other ecosystems are analyzed from the URL itself.
     */
    public void requireListedHost(String ecosystem, URI artifactUrl) {
        if ("pypi".equals(ecosystem) && !UrlPolicy.hostMatches(artifactUrl, pypiHosts)) {
            throw new IllegalArgumentException("The PyPI artifact host " + UrlPolicy.authorityOf(artifactUrl)
                    + " is not served by registries.pypi-url (see registries.pypi-file-hosts)");
        }
    }

    public record ReleaseArtifacts(List<URI> files) {

        public ReleaseArtifacts {
            files = List.copyOf(files);
        }
    }

    public ReleaseArtifacts resolve(AnalysisJob job) throws IOException {
        URI requested = urlPolicy.requireArtifactUrl(job.artifactUrl());
        return switch (job.ecosystem()) {
            case "npm" -> new ReleaseArtifacts(List.of(NpmLayout.requireTarball(requested, job.name(), job.version())));
            case "pypi" -> pypi(job, requested);
            case "maven" -> maven(job, requested);
            default -> throw new IllegalArgumentException("Unsupported ecosystem " + job.ecosystem());
        };
    }

    // Checked again here for jobs queued before the configuration changed: such a job fails, it is
    // not analyzed from the wrong index.
    private ReleaseArtifacts pypi(AnalysisJob job, URI requested) throws IOException {
        requireListedHost(job.ecosystem(), requested);
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
