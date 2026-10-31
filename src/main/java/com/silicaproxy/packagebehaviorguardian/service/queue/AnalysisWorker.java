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
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisResult;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.service.statics.HostileArtifactException;
import com.silicaproxy.packagebehaviorguardian.service.statics.Texts;
import com.silicaproxy.packagebehaviorguardian.service.verdict.Decision;
import com.silicaproxy.packagebehaviorguardian.service.verdict.VerdictPolicy;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Claims queued jobs and runs {@link AnalysisPipeline} on them, at most {@code queue.concurrency} at
 * a time per instance, each on its own virtual thread. A job the package itself makes impossible to
 * analyze ({@link HostileArtifactException}) ends BLOCKED by PBG-001. Any other failure sends the
 * job back to the queue after {@code retry-backoff-seconds × attempt}, then makes it FAILED: no
 * verdict is sent for an infrastructure failure (SilicaProxy's pending entry times out and its
 * fail-open/fail-closed policy applies), and the next check of that version re-queues it.
 */
@Component
@NullMarked
public class AnalysisWorker {

    private static final Logger LOG = LoggerFactory.getLogger(AnalysisWorker.class);
    private static final int MAX_ERROR_LENGTH = 1000;
    // A RUNNING job whose lease expired (its instance died) is claimed again by another one. The
    // lease of a job still being analyzed is renewed every minute, so a long analysis keeps it --
    // up to queue.max-job-minutes: past that it is presumed stuck, interrupted and no longer renewed.
    private static final Duration LEASE = Duration.ofMinutes(5);

    private final AnalysisJobRepository jobRepository;
    private final AnalysisPipeline pipeline;
    private final VerdictPolicy verdictPolicy;
    private final JobCompletion jobCompletion;
    private final PackageBehaviorGuardianProperties properties;
    private final AnalysisMetrics metrics;
    private final String workerId = "worker-" + UUID.randomUUID();
    private final Map<UUID, RunningJob> inFlight = new ConcurrentHashMap<>();
    private volatile boolean stopping;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public AnalysisWorker(AnalysisJobRepository jobRepository, AnalysisPipeline pipeline, VerdictPolicy verdictPolicy,
            JobCompletion jobCompletion, PackageBehaviorGuardianProperties properties, AnalysisMetrics metrics) {
        this.jobRepository = jobRepository;
        this.pipeline = pipeline;
        this.verdictPolicy = verdictPolicy;
        this.jobCompletion = jobCompletion;
        this.properties = properties;
        this.metrics = metrics;
    }

    @Scheduled(fixedDelayString = "${packagebehaviorguardian.queue.poll-interval-ms:1000}")
    public void poll() {
        PackageBehaviorGuardianProperties.QueueProperties queue = properties.queue();
        int free = queue.concurrency() - inFlight.size();
        if (free <= 0 || stopping) {
            return;
        }
        List<AnalysisJob> jobs;
        try {
            jobRepository.failAbandoned(queue.maxAttempts());
            jobs = jobRepository.claim(workerId, free, LEASE, queue.maxAttempts());
        } catch (DataAccessException e) {
            LOG.warn("Could not poll the analysis queue: {}", e.getMessage());
            return;
        }
        for (AnalysisJob job : jobs) {
            RunningJob running = new RunningJob(Instant.now());
            inFlight.put(job.id(), running);
            running.task = executor.submit(() -> {
                try {
                    process(job);
                } finally {
                    inFlight.remove(job.id());
                }
            });
        }
    }

    @Scheduled(fixedDelay = 60_000)
    public void renewLeases() {
        renewLeases(Instant.now());
    }

    void renewLeases(Instant now) {
        Duration maxJob = Duration.ofMinutes(properties.queue().maxJobMinutes());
        List<UUID> renewed = new ArrayList<>();
        inFlight.forEach((id, running) -> {
            if (Duration.between(running.startedAt, now).compareTo(maxJob) < 0) {
                renewed.add(id);
            } else {
                abandon(id, running, maxJob);
            }
        });
        try {
            jobRepository.renewLeases(renewed, workerId, LEASE);
        } catch (DataAccessException e) {
            LOG.warn("Could not renew the analysis leases: {}", e.getMessage());
        }
    }

    // The slot stays taken until the thread actually ends: the interrupt fails a blocked download
    // or scanner, and the job, whose lease now expires, is retried elsewhere if it did not stop.
    private static void abandon(UUID id, RunningJob running, Duration maxJob) {
        if (!running.overdue) {
            running.overdue = true;
            LOG.warn("Analysis of job {} still running after {} min: interrupted, its lease is no longer renewed",
                    id, maxJob.toMinutes());
        }
        Future<?> task = running.task;
        if (task != null) {
            task.cancel(true);
        }
    }

    void process(AnalysisJob job) {
        Timer.Sample sample = metrics.started(job);
        try {
            complete(job, pipeline.run(job));
        } catch (HostileArtifactException e) {
            if (e.mayBeTransient() && job.attempts() < properties.queue().maxAttempts()) {
                fail(job, e);
            } else {
                complete(job, AnalysisPipeline.Outcome.analysisImpossible(e));
            }
        } catch (IOException | RuntimeException e) {
            fail(job, e);
        } finally {
            metrics.finished(job, sample);
        }
    }

    private void complete(AnalysisJob job, AnalysisPipeline.Outcome outcome) {
        Decision decision = verdictPolicy.decide(job.ecosystem(), job.name(), job.version(), outcome.findings());
        boolean stored = jobCompletion.complete(new AnalysisResult(job.id(), properties.analysis().ruleSetVersion(),
                decision.verdict(), decision.score(), outcome.artifacts(), outcome.findings(), Instant.now()), workerId);
        if (!stored) {
            LOG.warn("Analysis of job {} finished after its lease was taken over: result discarded", job.id());
            return;
        }
        metrics.verdict(job, decision, outcome.findings());
        LOG.info("Analysis of {}/{}@{} done: {} (score {}, {} finding(s))", job.ecosystem(),
                LogSanitizer.sanitize(job.name()), LogSanitizer.sanitize(job.version()), decision.verdict(),
                decision.score(), outcome.findings().size());
    }

    private void fail(AnalysisJob job, Exception e) {
        if (stopping) {
            return; // interrupted by the shutdown: shutdown() hands the job back without spending an attempt
        }
        PackageBehaviorGuardianProperties.QueueProperties queue = properties.queue();
        boolean retry = job.attempts() < queue.maxAttempts();
        String error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getClass().getSimpleName() + ": " + e.getMessage();
        RunningJob running = inFlight.get(job.id());
        if (running != null && running.overdue) {
            Thread.interrupted(); // clears the overdue interrupt, so that the failure can still be recorded
            error = "Analysis exceeded " + queue.maxJobMinutes() + " min (queue.max-job-minutes): " + error;
        }
        String bounded = Texts.clip(error.length() > MAX_ERROR_LENGTH ? error.substring(0, MAX_ERROR_LENGTH) : error);
        metrics.failure(job);
        LOG.warn("Analysis of {}/{}@{} failed (attempt {}/{}{}): {}", job.ecosystem(), LogSanitizer.sanitize(job.name()),
                LogSanitizer.sanitize(job.version()), job.attempts(), queue.maxAttempts(), retry ? ", will retry" : ", giving up",
                LogSanitizer.sanitize(bounded));
        try {
            jobRepository.markFailed(job.id(), workerId, bounded, retry,
                    Duration.ofSeconds((long) queue.retryBackoffSeconds() * job.attempts()));
        } catch (DataAccessException dbError) {
            // The lease expires and the job is claimed again: nothing is lost.
            LOG.warn("Could not record the failure of job {}: {}", job.id(), dbError.getMessage());
        }
    }

    @PreDestroy
    public void shutdown() {
        stopping = true;
        executor.shutdownNow();
        try {
            jobRepository.release(List.copyOf(inFlight.keySet()), workerId);
        } catch (DataAccessException e) {
            LOG.warn("Could not release in-flight jobs on shutdown (their lease will expire): {}", e.getMessage());
        }
    }

    /** A job analyzed by this instance: when it started, and its task, to interrupt it once overdue. */
    private static final class RunningJob {

        private final Instant startedAt;
        private volatile @Nullable Future<?> task;
        private volatile boolean overdue;

        RunningJob(Instant startedAt) {
            this.startedAt = startedAt;
        }
    }
}
