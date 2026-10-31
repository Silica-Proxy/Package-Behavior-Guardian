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


package com.silicaproxy.packagebehaviorguardian.service.statics;

import com.silicaproxy.packagebehaviorguardian.dao.repository.ScanCacheRepository;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.AnalysisProperties;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;

/**
 * Findings of a {@link FileScanner} on one file, reused by (SHA-256, {@link FileScanner#cacheKey},
 * rule set): the same file -- shared by several versions or packages, or analyzed again after a
 * requeue -- runs the scanner once. Only a complete scan is stored: a failing scanner throws before
 * anything is cached, so a failure is never replayed as a clean result. The file's local name, which
 * differs from one job to the next, is stored as {@link #ARTIFACT_PLACEHOLDER} and put back on reuse.
 * The cache is an optimization only: a database error falls back to running the scanner.
 */
@Component
@NullMarked
public class ScanCache {

    // Never a local file name: those are reduced to [A-Za-z0-9._-] by the pipeline.
    static final String ARTIFACT_PLACEHOLDER = "{artifact}";

    private static final Logger LOG = LoggerFactory.getLogger(ScanCache.class);

    private final ScanCacheRepository repository;
    private final AnalysisProperties properties;

    public ScanCache(ScanCacheRepository repository, PackageBehaviorGuardianProperties properties) {
        this.repository = repository;
        this.properties = properties.analysis();
    }

    public List<Finding> scan(FileScanner scanner, String ecosystem, Path artifact, String sha256, Path workDir) throws IOException {
        if (!properties.scanCacheEnabled()) {
            return scanner.scanFile(ecosystem, artifact, workDir);
        }
        String fileName = String.valueOf(artifact.getFileName());
        String key = scanner.cacheKey(ecosystem);
        Optional<List<Finding>> cached = lookup(sha256, key);
        if (cached.isPresent()) {
            LOG.debug("{} findings of {} reused from the scan cache", key, sha256);
            return relabel(cached.get(), ARTIFACT_PLACEHOLDER, fileName);
        }
        List<Finding> findings = scanner.scanFile(ecosystem, artifact, workDir);
        store(sha256, key, relabel(findings, fileName, ARTIFACT_PLACEHOLDER));
        return findings;
    }

    @Scheduled(initialDelay = 1, fixedDelay = 360, timeUnit = TimeUnit.MINUTES)
    @SchedulerLock(name = "pbg-scan-cache-purge", lockAtLeastFor = "PT1M")
    public void purge() {
        try {
            int purged = repository.purge(properties.ruleSetVersion(),
                    Instant.now().minus(Duration.ofDays(properties.scanCacheMaxAgeDays())));
            if (purged > 0) {
                LOG.info("Purged {} scan cache entr{} of an older rule set or past {} days", purged, purged == 1 ? "y" : "ies",
                        properties.scanCacheMaxAgeDays());
            }
        } catch (DataAccessException e) {
            LOG.warn("Could not purge the scan cache: {}", e.getMessage());
        }
    }

    private Optional<List<Finding>> lookup(String sha256, String key) {
        try {
            return repository.find(sha256, key, properties.ruleSetVersion());
        } catch (DataAccessException | JacksonException e) {
            LOG.warn("Scan cache unavailable, scanning {} with {}: {}", sha256, key, e.getMessage());
            return Optional.empty();
        }
    }

    private void store(String sha256, String key, List<Finding> findings) {
        try {
            repository.put(sha256, key, properties.ruleSetVersion(), findings);
        } catch (DataAccessException e) {
            LOG.warn("Could not store the {} findings of {} in the scan cache: {}", key, sha256, e.getMessage());
        }
    }

    /**
     * Replaces the file name {@code from} by {@code to}: at the start of each location (where the
     * parsers put it) and anywhere in messages. Texts are clipped again, a longer name could overflow.
     */
    static List<Finding> relabel(List<Finding> findings, String from, String to) {
        return findings.stream()
                .map(finding -> new Finding(finding.ruleId(), finding.severity(), finding.scanner(),
                        Texts.clip(finding.message().replace(from, to)), relabelLocation(finding.location(), from, to)))
                .toList();
    }

    private static @Nullable String relabelLocation(@Nullable String location, String from, String to) {
        if (location == null || !location.startsWith(from)) {
            return location;
        }
        return Texts.clip(to + location.substring(from.length()));
    }
}
