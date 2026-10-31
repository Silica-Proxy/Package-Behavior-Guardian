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
package com.silicaproxy.packagebehaviorguardian.service.audit;

import com.silicaproxy.packagebehaviorguardian.config.LogSanitizer;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AuditRepository;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisAudit;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.CheckAudit;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.service.queue.AnalysisPipeline;
import com.silicaproxy.packagebehaviorguardian.service.verdict.Decision;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Builds the audit rows and writes them. An audit write that fails is logged, never fails the caller:
 * the audit must not become a point of failure of the verdict flow. A DONE analysis is written in the
 * transaction that stores its verdict, under a savepoint: committed together when the write succeeds,
 * and the verdict still committed when it fails. A failed attempt, a lost lease and a check are
 * written on their own. Each row is also logged on the {@code audit} logger.
 */
@Service
@NullMarked
public class AuditService {

    private static final Logger LOG = LoggerFactory.getLogger(AuditService.class);
    private static final Logger AUDIT = LoggerFactory.getLogger("audit");

    static final String LEASE_EXPIRED = "worker lease expired";

    private final AuditRepository repository;
    private final PackageBehaviorGuardianProperties.AnalysisProperties analysis;
    private final TransactionTemplate savepoint;

    public AuditService(AuditRepository repository, PackageBehaviorGuardianProperties properties,
            PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.analysis = properties.analysis();
        this.savepoint = new TransactionTemplate(transactionManager);
        this.savepoint.setPropagationBehavior(TransactionDefinition.PROPAGATION_NESTED);
    }

    public AnalysisAudit analysisDone(AnalysisJob job, String workerId, Instant startedAt, Instant finishedAt,
            AnalysisPipeline.Outcome outcome, Decision decision) {
        AnalysisPipeline.StageTimings timings = outcome.timings();
        return new AnalysisAudit(job.id(), job.attempts(), workerId, AnalysisAudit.Outcome.DONE, job.ecosystem(),
                job.name(), job.version(), job.artifactUrl(), decision.verdict(), decision.score(), decision.reason(),
                decision.blockingRules(), decision.counted(), decision.allowlisted(), outcome.artifacts(), null,
                job.queuedAt(), startedAt, finishedAt, millis(job.queuedAt(), startedAt), millis(startedAt, finishedAt),
                timings.resolveMs(), timings.downloadMs(), timings.scanMs(), analysis.ruleSetVersion(),
                analysis.highWeight(), analysis.mediumWeight(), analysis.blockThreshold());
    }

    public AnalysisAudit analysisFailed(AnalysisJob job, String workerId, Instant startedAt, Instant finishedAt,
            String error, boolean retry) {
        return new AnalysisAudit(job.id(), job.attempts(), workerId,
                retry ? AnalysisAudit.Outcome.RETRY : AnalysisAudit.Outcome.FAILED, job.ecosystem(), job.name(),
                job.version(), job.artifactUrl(), null, null, null, List.of(), List.of(), List.of(), List.of(), error,
                job.queuedAt(), startedAt, finishedAt, millis(job.queuedAt(), startedAt), millis(startedAt, finishedAt),
                null, null, null, analysis.ruleSetVersion(), null, null, null);
    }

    /**
     * An attempt that ended because its worker vanished: EXPIRED when the job was claimed again,
     * ABANDONED when it was given up (no attempt left). When it started is not known.
     */
    public AnalysisAudit leaseLost(AnalysisJobRepository.LostLease lost, AnalysisAudit.Outcome outcome, Instant finishedAt) {
        AnalysisJob job = lost.job();
        String error = outcome == AnalysisAudit.Outcome.EXPIRED || job.lastError() == null ? LEASE_EXPIRED : job.lastError();
        return new AnalysisAudit(job.id(), lost.attempt(), lost.workerId(), outcome, job.ecosystem(), job.name(),
                job.version(), job.artifactUrl(), null, null, null, List.of(), List.of(), List.of(), List.of(), error,
                job.queuedAt(), null, finishedAt, null, null, null, null, null, analysis.ruleSetVersion(), null, null, null);
    }

    /** Writes the attempts lost by jobs claimed again (EXPIRED); a write failure is only logged. */
    public void recordExpired(List<AnalysisJobRepository.LostLease> lost) {
        recordLeasesLost(lost, AnalysisAudit.Outcome.EXPIRED);
    }

    /** Writes the jobs given up with no attempt left (ABANDONED); a write failure is only logged. */
    public void recordAbandoned(List<AnalysisJobRepository.LostLease> lost) {
        recordLeasesLost(lost, AnalysisAudit.Outcome.ABANDONED);
    }

    private void recordLeasesLost(List<AnalysisJobRepository.LostLease> lost, AnalysisAudit.Outcome outcome) {
        Instant now = Instant.now();
        lost.forEach(lease -> record(leaseLost(lease, outcome, now)));
    }

    /**
     * Writes the audit row of a stored verdict, in the caller's transaction but under a savepoint:
     * a write failure is rolled back to it and logged, the verdict is still committed. The row is
     * logged once the transaction commits.
     */
    public void recordWithVerdict(AnalysisAudit audit) {
        try {
            savepoint.executeWithoutResult(status -> repository.insert(audit));
        } catch (DataAccessException | TransactionException e) {
            LOG.error("Could not write the audit of job {} (attempt {}), verdict stored anyway: {}", audit.jobId(),
                    audit.attempt(), e.getMessage());
        }
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    log(audit);
                }
            });
        } else {
            log(audit);
        }
    }

    /** Writes a failed attempt; a write failure is only logged. */
    public void record(AnalysisAudit audit) {
        try {
            repository.insert(audit);
        } catch (DataAccessException e) {
            LOG.error("Could not write the audit of job {} (attempt {}): {}", audit.jobId(), audit.attempt(), e.getMessage());
        }
        log(audit);
    }

    /** Writes a check; a write failure is only logged. */
    public void record(CheckAudit audit) {
        try {
            repository.insert(audit);
        } catch (DataAccessException e) {
            LOG.error("Could not write the audit of a check of {}/{}@{}: {}", audit.ecosystem(),
                    LogSanitizer.sanitize(audit.requestedName()), LogSanitizer.sanitize(audit.version()), e.getMessage());
        }
        AUDIT.info("check ecosystem={} name={} version={} status={} http={} verdict={} durationMs={} job={} callbackHost={}"
                        + " client={} reason=\"{}\"",
                audit.ecosystem(), LogSanitizer.sanitize(audit.requestedName()), LogSanitizer.sanitize(audit.version()),
                audit.responseStatus(), audit.httpStatus(), audit.verdict(), audit.durationMs(), audit.jobId(),
                LogSanitizer.sanitize(audit.callbackHost()), LogSanitizer.sanitize(audit.clientAddress()),
                LogSanitizer.sanitize(audit.reason()));
    }

    /** Logs an analysis audit row (already written). */
    public void log(AnalysisAudit audit) {
        AUDIT.info("analysis ecosystem={} name={} version={} outcome={} verdict={} score={} rules={} attempt={}"
                        + " waitMs={} runMs={} job={} reason=\"{}\" error=\"{}\"",
                audit.ecosystem(), LogSanitizer.sanitize(audit.name()), LogSanitizer.sanitize(audit.version()),
                audit.outcome(), audit.verdict(), audit.score(), String.join(",", audit.blockingRules()), audit.attempt(),
                audit.waitMs(), audit.runMs(), audit.jobId(), LogSanitizer.sanitize(audit.reason()),
                LogSanitizer.sanitize(audit.error()));
    }

    private static Long millis(Instant from, Instant to) {
        return Math.max(0, Duration.between(from, to).toMillis());
    }
}
