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

import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisResultRepository;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisAudit;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisResult;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.service.audit.AuditService;
import com.silicaproxy.packagebehaviorguardian.service.verdict.Decision;
import java.time.Instant;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Stores a result and marks its job DONE atomically: the callback dispatcher only picks up DONE jobs,
 * so it never sees a DONE job without its result. The audit row is written in the same transaction,
 * under a savepoint (see {@link AuditService#recordWithVerdict}): a failing audit write never costs
 * the verdict. A worker that lost its lease is rolled back.
 */
@Component
@NullMarked
public class JobCompletion {

    private final AnalysisJobRepository jobRepository;
    private final AnalysisResultRepository resultRepository;
    private final AuditService auditService;
    private final String ruleSetVersion;

    public JobCompletion(AnalysisJobRepository jobRepository, AnalysisResultRepository resultRepository,
            AuditService auditService, PackageBehaviorGuardianProperties properties) {
        this.jobRepository = jobRepository;
        this.resultRepository = resultRepository;
        this.auditService = auditService;
        this.ruleSetVersion = properties.analysis().ruleSetVersion();
    }

    /** False (and nothing stored) when {@code workerId} no longer holds the job. */
    @Transactional
    public boolean complete(AnalysisJob job, String workerId, Instant startedAt, AnalysisPipeline.Outcome outcome,
            Decision decision) {
        if (!jobRepository.markDone(job.id(), workerId)) {
            return false;
        }
        Instant finishedAt = Instant.now();
        resultRepository.upsert(new AnalysisResult(job.id(), ruleSetVersion, outcome.artifacts(), outcome.findings(), finishedAt));
        AnalysisAudit audit = auditService.analysisDone(job, workerId, startedAt, finishedAt, outcome, decision);
        auditService.recordWithVerdict(audit);
        return true;
    }
}
