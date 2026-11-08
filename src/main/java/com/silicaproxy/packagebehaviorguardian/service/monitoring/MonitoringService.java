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


package com.silicaproxy.packagebehaviorguardian.service.monitoring;

import com.silicaproxy.packagebehaviorguardian.dao.repository.AllowlistRepository.SyncState;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.HealthCheckRepository;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.service.allowlist.AllowlistStore;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;

/**
 * Aggregates the health of packagebehaviorguardian (database, analysis queue) into UP / DOWN /
 * DEGRADED. The queue is DEGRADED when its oldest PENDING job waited longer than {@code
 * queue.max-wait-minutes}: verdicts would then arrive after SilicaProxy's pending TTL. The GitOps
 * allowlist is DEGRADED when its last synchronization failed, skipped invalid entries or is older
 * than {@code gitops.max-age-minutes}: the entries in force may then not be the repository's.
 */
@Service
@NullMarked
public class MonitoringService {

    private final HealthCheckRepository healthCheckRepository;
    private final AnalysisJobRepository jobRepository;
    private final PackageBehaviorGuardianProperties properties;
    private final AllowlistStore allowlistStore;

    public MonitoringService(HealthCheckRepository healthCheckRepository, AnalysisJobRepository jobRepository,
            PackageBehaviorGuardianProperties properties, AllowlistStore allowlistStore) {
        this.healthCheckRepository = healthCheckRepository;
        this.jobRepository = jobRepository;
        this.properties = properties;
        this.allowlistStore = allowlistStore;
    }

    public record ComponentHealth(String status, Map<String, Object> details) {
        public ComponentHealth {
            details = Collections.unmodifiableMap(new HashMap<>(details));
        }
    }

    public record HealthReport(String status, Map<String, ComponentHealth> components) {
        public HealthReport {
            components = Collections.unmodifiableMap(new HashMap<>(components));
        }
    }

    public HealthReport checkHealth() {
        Map<String, ComponentHealth> components = new HashMap<>();
        components.put("database", databaseHealth());
        components.put("analysisQueue", queueHealth());
        components.put("gitops", gitopsHealth());
        String overallStatus = "UP";
        for (ComponentHealth component : components.values()) {
            overallStatus = worseOf(overallStatus, component.status());
        }
        return new HealthReport(overallStatus, components);
    }

    private static String worseOf(String currentWorst, String candidate) {
        if ("DOWN".equals(currentWorst) || "DOWN".equals(candidate)) {
            return "DOWN";
        }
        if ("DEGRADED".equals(currentWorst) || "DEGRADED".equals(candidate)) {
            return "DEGRADED";
        }
        return "UP";
    }

    public ComponentHealth databaseHealth() {
        Map<String, Object> details = new HashMap<>();
        try {
            healthCheckRepository.isDatabaseReachable();
            details.put("message", "Database connection OK");
            return new ComponentHealth("UP", details);
        } catch (RuntimeException e) {
            details.put("error", String.valueOf(e.getMessage()));
            return new ComponentHealth("DOWN", details);
        }
    }

    public ComponentHealth queueHealth() {
        Map<String, Object> details = new HashMap<>();
        try {
            details.put("depth", jobRepository.countPending());
            Optional<Instant> oldest = jobRepository.oldestPendingQueuedAt();
            long waitMinutes = oldest.map(instant -> Duration.between(instant, Instant.now()).toMinutes()).orElse(0L);
            details.put("oldestWaitMinutes", waitMinutes);
            details.put("maxWaitMinutes", properties.queue().maxWaitMinutes());
            return new ComponentHealth(waitMinutes > properties.queue().maxWaitMinutes() ? "DEGRADED" : "UP", details);
        } catch (RuntimeException e) {
            details.put("error", String.valueOf(e.getMessage()));
            return new ComponentHealth("DOWN", details);
        }
    }

    public ComponentHealth gitopsHealth() {
        Map<String, Object> details = new HashMap<>();
        details.put("enabled", allowlistStore.gitopsEnabled());
        details.put("entriesInForce", allowlistStore.entries().size());
        if (!allowlistStore.gitopsEnabled()) {
            return new ComponentHealth("UP", details);
        }
        SyncState state = allowlistStore.state();
        if (state == null) {
            details.put("message", "GitOps allowlist not loaded from the database yet");
            return new ComponentHealth("DEGRADED", details);
        }
        details.put("revision", String.valueOf(state.revision()));
        details.put("entries", state.entries());
        details.put("skipped", state.skipped());
        String lastError = state.lastError();
        if (lastError != null) {
            details.put("lastError", lastError);
        }
        Instant syncedAt = state.syncedAt();
        if (syncedAt == null) {
            details.put("message", "First synchronization pending");
            return new ComponentHealth(lastError == null ? "UP" : "DEGRADED", details);
        }
        long ageMinutes = Duration.between(syncedAt, Instant.now()).toMinutes();
        details.put("syncedAt", syncedAt.toString());
        details.put("ageMinutes", ageMinutes);
        boolean degraded = lastError != null || state.skipped() > 0
                || ageMinutes > properties.gitops().maxAgeMinutes();
        return new ComponentHealth(degraded ? "DEGRADED" : "UP", details);
    }
}
