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
import com.silicaproxy.packagebehaviorguardian.model.dto.ReportResponse;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisResult;
import com.silicaproxy.packagebehaviorguardian.service.verdict.Decision;
import com.silicaproxy.packagebehaviorguardian.service.verdict.VerdictPolicy;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;

/** Builds the full report of {@code GET /v1/reports}, with the verdict as it stands now (current allowlist). */
@Service
@NullMarked
public class ReportService {

    private final AnalysisJobRepository jobRepository;
    private final AnalysisResultRepository resultRepository;
    private final VerdictPolicy verdictPolicy;

    public ReportService(AnalysisJobRepository jobRepository, AnalysisResultRepository resultRepository, VerdictPolicy verdictPolicy) {
        this.jobRepository = jobRepository;
        this.resultRepository = resultRepository;
        this.verdictPolicy = verdictPolicy;
    }

    public Optional<ReportResponse> report(String ecosystem, String name, String version) {
        return jobRepository.find(ecosystem, name, version).map(this::toReport);
    }

    private ReportResponse toReport(AnalysisJob job) {
        Optional<AnalysisResult> result = resultRepository.findByJobId(job.id());
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
