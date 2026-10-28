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

import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.HealthCheckRepository;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
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
 * queue.max-wait-minutes}: verdicts would then arrive after SilicaProxy's pending TTL.
 */
@Service
@NullMarked
public class MonitoringService {

    private final HealthCheckRepository healthCheckRepository;
    private final AnalysisJobRepository jobRepository;
    private final PackageBehaviorGuardianProperties properties;

    public MonitoringService(HealthCheckRepository healthCheckRepository, AnalysisJobRepository jobRepository,
            PackageBehaviorGuardianProperties properties) {
        this.healthCheckRepository = healthCheckRepository;
        this.jobRepository = jobRepository;
        this.properties = properties;
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
}
