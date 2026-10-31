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


package com.silicaproxy.packagebehaviorguardian.service.report;

import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisResultRepository;
import com.silicaproxy.packagebehaviorguardian.model.PackageNames;
import com.silicaproxy.packagebehaviorguardian.model.dto.ReportResponse;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisResult;
import com.silicaproxy.packagebehaviorguardian.model.entity.JobStatus;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.service.verdict.Decision;
import com.silicaproxy.packagebehaviorguardian.service.verdict.VerdictPolicy;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;

/**
 * Builds the full report of {@code GET /v1/reports}, with the verdict as it stands now (current allowlist).
 * Only a DONE job analyzed under the current rule set has one -- the same rule as {@code POST /v1/check}: while
 * a requeued job waits or runs, its previous result is not served as if it were the answer. The name is
 * looked up in its canonical form ({@link PackageNames}), as at intake.
 */
@Service
@NullMarked
public class ReportService {

    /** Status of a DONE job whose result predates the current rule set: the next check re-analyzes it. */
    static final String OUTDATED = "OUTDATED";

    private final AnalysisJobRepository jobRepository;
    private final AnalysisResultRepository resultRepository;
    private final VerdictPolicy verdictPolicy;
    private final String ruleSetVersion;

    public ReportService(AnalysisJobRepository jobRepository, AnalysisResultRepository resultRepository, VerdictPolicy verdictPolicy,
            PackageBehaviorGuardianProperties properties) {
        this.jobRepository = jobRepository;
        this.resultRepository = resultRepository;
        this.verdictPolicy = verdictPolicy;
        this.ruleSetVersion = properties.analysis().ruleSetVersion();
    }

    public Optional<ReportResponse> report(String ecosystem, String name, String version) {
        return jobRepository.find(ecosystem, PackageNames.normalize(ecosystem, name), version).map(this::toReport);
    }

    private ReportResponse toReport(AnalysisJob job) {
        Optional<AnalysisResult> result = job.status() == JobStatus.DONE ? resultRepository.findByJobId(job.id()) : Optional.empty();
        if (result.isPresent() && !ruleSetVersion.equals(result.get().ruleSetVersion())) {
            return new ReportResponse(job.ecosystem(), job.name(), job.version(), OUTDATED, job.attempts(), job.lastError(),
                    null, null, null, result.get().ruleSetVersion(), result.get().finishedAt(), result.get().artifacts(),
                    List.of(), List.of());
        }
        if (result.isEmpty()) {
            return new ReportResponse(job.ecosystem(), job.name(), job.version(), job.status().name(), job.attempts(),
                    job.lastError(), null, null, null, null, null, List.of(), List.of(), List.of());
        }
        AnalysisResult r = result.get();
        Decision decision = verdictPolicy.decide(job.ecosystem(), job.name(), job.version(), r.findings());
        return new ReportResponse(job.ecosystem(), job.name(), job.version(), job.status().name(), job.attempts(),
                job.lastError(), decision.verdict(), decision.reason(), decision.score(), r.ruleSetVersion(),
                r.finishedAt(), r.artifacts(), decision.counted(), decision.allowlisted());
    }
}
