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

import com.silicaproxy.packagebehaviorguardian.config.LogSanitizer;
import com.silicaproxy.packagebehaviorguardian.config.Metrics;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AllowlistRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AllowlistRepository.SyncState;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.AllowlistEntry;
import com.silicaproxy.packagebehaviorguardian.service.verdict.AllowlistSource;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The allowlist in force on this instance: the static entries of the configuration, plus the GitOps
 * entries of the database, reloaded whenever a synchronization (on any instance) bumped their
 * generation. Read on every verdict, so kept in memory; loaded once at startup, before any verdict.
 */
@Component
@NullMarked
public class AllowlistStore implements AllowlistSource {

    private static final Logger LOG = LoggerFactory.getLogger(AllowlistStore.class);

    private final AllowlistRepository repository;
    private final List<AllowlistEntry> configured;
    private final boolean gitopsEnabled;

    private static final int MAX_LOGGED_CHANGES = 50;

    private volatile List<AllowlistEntry> entries;
    private List<AllowlistEntry> gitopsEntries = List.of();
    private volatile long generation = -1;
    private volatile @Nullable SyncState state;

    public AllowlistStore(AllowlistRepository repository, PackageBehaviorGuardianProperties properties,
            MeterRegistry meterRegistry) {
        this.repository = repository;
        this.configured = List.copyOf(properties.allowlist());
        this.gitopsEnabled = properties.gitops().enabled();
        this.entries = configured;
        Gauge.builder(Metrics.ALLOWLIST_ENTRIES_METRIC, this, store -> store.entries.size())
                .description("Allowlist entries in force on this instance (configuration and GitOps)")
                .register(meterRegistry);
        Gauge.builder(Metrics.GITOPS_AGE_METRIC, this, AllowlistStore::secondsSinceSync)
                .description("Seconds since the last successful GitOps allowlist synchronization (NaN if none)")
                .register(meterRegistry);
        reload();
    }

    @Override
    public List<AllowlistEntry> entries() {
        return entries;
    }

    /** The last synchronization seen, null before the first read of the database. */
    public @Nullable SyncState state() {
        return state;
    }

    public boolean gitopsEnabled() {
        return gitopsEnabled;
    }

    /**
     * Reloads the GitOps entries if their generation changed. With {@code gitops.enabled} false the
     * table is ignored: only the configured entries apply.
     */
    @Scheduled(fixedDelayString = "#{${packagebehaviorguardian.gitops.refresh-interval-seconds:30} * 1000}",
            initialDelayString = "#{${packagebehaviorguardian.gitops.refresh-interval-seconds:30} * 1000}")
    public void refresh() {
        reload();
    }

    private synchronized void reload() {
        if (!gitopsEnabled) {
            return;
        }
        try {
            SyncState current = repository.state();
            state = current;
            if (current.generation() != generation) {
                List<AllowlistEntry> loaded = repository.entries();
                List<AllowlistEntry> merged = new ArrayList<>(configured);
                merged.addAll(loaded);
                entries = List.copyOf(merged);
                boolean firstLoad = generation < 0;
                generation = current.generation();
                LOG.info("Allowlist reloaded: {} GitOps entries (commit {}, generation {}), {} configured",
                        loaded.size(), current.revision(), generation, configured.size());
                if (!firstLoad) {
                    logChanges(gitopsEntries, loaded);
                }
                gitopsEntries = loaded;
            }
        } catch (DataAccessException e) {
            LOG.warn("Could not reload the GitOps allowlist, the entries in force are kept: {}", e.getMessage());
        }
    }

    // What a reviewer looks for in the logs: which exclusion came in or went out, and why.
    private static void logChanges(List<AllowlistEntry> before, List<AllowlistEntry> after) {
        List<AllowlistEntry> added = after.stream().filter(entry -> !before.contains(entry)).toList();
        List<AllowlistEntry> removed = before.stream().filter(entry -> !after.contains(entry)).toList();
        added.stream().limit(MAX_LOGGED_CHANGES).forEach(entry -> LOG.info("Allowlist entry added: {}", describe(entry)));
        removed.stream().limit(MAX_LOGGED_CHANGES).forEach(entry -> LOG.info("Allowlist entry removed: {}", describe(entry)));
        if (added.size() > MAX_LOGGED_CHANGES || removed.size() > MAX_LOGGED_CHANGES) {
            LOG.info("Allowlist: {} entries added and {} removed in all, only the first {} of each logged",
                    added.size(), removed.size(), MAX_LOGGED_CHANGES);
        }
    }

    static String describe(AllowlistEntry entry) {
        String version = entry.version();
        String ruleId = entry.ruleId();
        String detail = entry.detail();
        return String.valueOf(LogSanitizer.sanitize(entry.ecosystem() + "/" + entry.name() + "@" + (version == null ? "*" : version)
                + " rule=" + (ruleId == null ? "*" : ruleId) + (detail == null ? "" : " detail=\"" + detail + "\"")
                + " reason=\"" + entry.reason() + "\""));
    }

    private double secondsSinceSync() {
        SyncState current = state;
        Instant syncedAt = current == null ? null : current.syncedAt();
        return syncedAt == null ? Double.NaN : Duration.between(syncedAt, Instant.now()).toSeconds();
    }
}
