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

import com.silicaproxy.packagebehaviorguardian.config.Metrics;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.service.verdict.Decision;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NullMarked;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;

/** The analysis metrics: queue depth and wait, duration, verdicts, findings, failures. */
@Component
@NullMarked
public class AnalysisMetrics {

    private final MeterRegistry meterRegistry;

    public AnalysisMetrics(MeterRegistry meterRegistry, AnalysisJobRepository jobRepository) {
        this.meterRegistry = meterRegistry;
        Gauge.builder(Metrics.QUEUE_DEPTH_METRIC, jobRepository, AnalysisMetrics::safeDepth).register(meterRegistry);
    }

    /** Records how long the job waited in the queue and starts timing its analysis. */
    public Timer.Sample started(AnalysisJob job) {
        Timer.builder(Metrics.QUEUE_WAIT_METRIC).register(meterRegistry).record(Duration.between(job.queuedAt(), Instant.now()));
        return Timer.start(meterRegistry);
    }

    public void finished(AnalysisJob job, Timer.Sample sample) {
        sample.stop(Timer.builder(Metrics.ANALYSIS_DURATION_METRIC)
                .tag(Metrics.TAG_ECOSYSTEM, job.ecosystem()).tag(Metrics.TAG_PASS, Metrics.PASS_STATIC)
                .register(meterRegistry));
    }

    public void verdict(AnalysisJob job, Decision decision, List<Finding> findings) {
        meterRegistry.counter(Metrics.ANALYSIS_VERDICT_METRIC,
                Metrics.TAG_ECOSYSTEM, job.ecosystem(), Metrics.TAG_VERDICT, decision.verdict().name()).increment();
        findings.forEach(finding -> meterRegistry.counter(Metrics.FINDING_COUNT_METRIC,
                Metrics.TAG_RULE_ID, finding.ruleId(), Metrics.TAG_SCANNER, finding.scanner()).increment());
    }

    public void failure(AnalysisJob job) {
        meterRegistry.counter(Metrics.ANALYSIS_FAILURES_METRIC, Metrics.TAG_ECOSYSTEM, job.ecosystem()).increment();
    }

    private static double safeDepth(AnalysisJobRepository repository) {
        try {
            return repository.countPending();
        } catch (DataAccessException e) {
            return Double.NaN;
        }
    }
}
