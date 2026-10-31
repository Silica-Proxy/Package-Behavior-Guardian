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


package com.silicaproxy.packagebehaviorguardian.service.callback;

import com.silicaproxy.packagebehaviorguardian.config.Metrics;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisResultRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.PendingCallbackRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.PendingCallbackRepository.ClaimedCallback;
import com.silicaproxy.packagebehaviorguardian.model.dto.CallbackPayload;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisResult;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.CallbackProperties;
import com.silicaproxy.packagebehaviorguardian.service.verdict.Decision;
import com.silicaproxy.packagebehaviorguardian.service.verdict.VerdictPolicy;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.util.Optional;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Delivers verdicts to SilicaProxy ({@code POST /external-validation/callback/{token}}) for every
 * pending callback whose job is DONE. The verdict is recomputed at delivery time, so an allowlist
 * entry added in between is honored. 2xx: delivered. 404/410: SilicaProxy no longer knows the
 * token (already resolved, or expired) -- dropped. Anything else: retried with exponential
 * backoff capped at {@code callback.max-backoff-seconds}, then dropped after
 * {@code callback.max-attempts}. Runs on every instance; claiming
 * with SKIP LOCKED keeps two instances from sending the same callback.
 */
@Component
@NullMarked
public class CallbackDispatcher {

    private static final Logger LOG = LoggerFactory.getLogger(CallbackDispatcher.class);
    private static final int BATCH_SIZE = 20;
    // Longer than a whole batch delivered one by one (BATCH_SIZE x CallbackSender.TIMEOUT = 200 s), so
    // no callback of the batch can be claimed again while it waits its turn.
    private static final Duration LEASE = Duration.ofMinutes(5);

    private final PendingCallbackRepository callbackRepository;
    private final AnalysisJobRepository jobRepository;
    private final AnalysisResultRepository resultRepository;
    private final VerdictPolicy verdictPolicy;
    private final CallbackSender sender;
    private final MeterRegistry meterRegistry;
    private final CallbackProperties properties;

    public CallbackDispatcher(PendingCallbackRepository callbackRepository, AnalysisJobRepository jobRepository,
            AnalysisResultRepository resultRepository, VerdictPolicy verdictPolicy, CallbackSender sender,
            MeterRegistry meterRegistry, PackageBehaviorGuardianProperties properties) {
        this.callbackRepository = callbackRepository;
        this.jobRepository = jobRepository;
        this.resultRepository = resultRepository;
        this.verdictPolicy = verdictPolicy;
        this.sender = sender;
        this.meterRegistry = meterRegistry;
        this.properties = properties.callback();
    }

    @Scheduled(fixedDelayString = "${packagebehaviorguardian.callback.poll-interval-ms:2000}")
    public void dispatch() {
        try {
            callbackRepository.deleteForFailedJobs();
            for (ClaimedCallback callback : callbackRepository.claimDue(BATCH_SIZE, LEASE)) {
                deliver(callback);
            }
        } catch (DataAccessException e) {
            LOG.warn("Could not poll pending callbacks: {}", e.getMessage());
        }
    }

    private void deliver(ClaimedCallback callback) {
        Optional<AnalysisJob> job = jobRepository.findById(callback.jobId());
        Optional<AnalysisResult> result = resultRepository.findByJobId(callback.jobId());
        if (job.isEmpty() || result.isEmpty()) {
            callbackRepository.delete(callback.id());
            return;
        }
        Decision decision = verdictPolicy.decide(job.get().ecosystem(), job.get().name(), job.get().version(), result.get().findings());
        io.micrometer.core.instrument.Timer.Sample sample = io.micrometer.core.instrument.Timer.start(meterRegistry);
        int status = sender.send(callback.callbackUrl(), new CallbackPayload(decision.verdict(), decision.reason()));
        sample.stop(meterRegistry.timer(Metrics.CALLBACK_DURATION_METRIC));
        if (status / 100 == 2) {
            callbackRepository.delete(callback.id());
            meterRegistry.counter(Metrics.CALLBACK_METRIC, Metrics.TAG_RESULT, Metrics.RESULT_DELIVERED).increment();
        } else if (status == 404 || status == 410 || status == CallbackSender.REJECTED) {
            callbackRepository.delete(callback.id());
            meterRegistry.counter(Metrics.CALLBACK_METRIC, Metrics.TAG_RESULT, Metrics.RESULT_GONE).increment();
        } else if (callback.attempts() >= properties.maxAttempts()) {
            callbackRepository.giveUp(callback.id(), callback.attempts());
            meterRegistry.counter(Metrics.CALLBACK_FAILURES_METRIC).increment();
            LOG.error("Giving up callback {} for job {} after {} attempts (last status {})",
                    callback.id(), callback.jobId(), callback.attempts(), status);
        } else {
            callbackRepository.reschedule(callback.id(), properties.retryDelay(callback.attempts()));
            meterRegistry.counter(Metrics.CALLBACK_METRIC, Metrics.TAG_RESULT, Metrics.RESULT_RETRY).increment();
        }
    }
}
