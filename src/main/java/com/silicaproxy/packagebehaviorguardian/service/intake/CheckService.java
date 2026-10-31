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


package com.silicaproxy.packagebehaviorguardian.service.intake;

import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisResultRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.PendingCallbackRepository;
import com.silicaproxy.packagebehaviorguardian.model.PackageNames;
import com.silicaproxy.packagebehaviorguardian.model.dto.CheckRequest;
import com.silicaproxy.packagebehaviorguardian.model.dto.CheckResponse;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisResult;
import com.silicaproxy.packagebehaviorguardian.model.entity.JobStatus;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.service.artifact.ReleaseArtifactResolver;
import com.silicaproxy.packagebehaviorguardian.service.verdict.Decision;
import com.silicaproxy.packagebehaviorguardian.service.verdict.VerdictPolicy;
import java.net.URI;
import java.util.Optional;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * Backs {@code POST /v1/check}: validate both URLs and the package identity ({@link PackageIdentityPolicy}),
 * then either answer from the cache (a DONE job analyzed under the current rule set) or queue the version.
 * Either way the callback URL is recorded, and the verdict is delivered to it by
 * {@code CallbackDispatcher} as soon as the job is DONE -- immediately for a cached one.
 * Deduplication is by (ecosystem, canonical name, version) -- see {@link PackageNames}: concurrent
 * checks of one version share one job, whatever spelling of the name they use.
 */
@Service
@NullMarked
public class CheckService {

    private final UrlPolicy urlPolicy;
    private final AnalysisJobRepository jobRepository;
    private final AnalysisResultRepository resultRepository;
    private final PendingCallbackRepository callbackRepository;
    private final VerdictPolicy verdictPolicy;
    private final ReleaseArtifactResolver artifactResolver;
    private final String ruleSetVersion;

    public CheckService(UrlPolicy urlPolicy, AnalysisJobRepository jobRepository, AnalysisResultRepository resultRepository,
            PendingCallbackRepository callbackRepository, VerdictPolicy verdictPolicy, ReleaseArtifactResolver artifactResolver,
            PackageBehaviorGuardianProperties properties) {
        this.urlPolicy = urlPolicy;
        this.jobRepository = jobRepository;
        this.resultRepository = resultRepository;
        this.callbackRepository = callbackRepository;
        this.verdictPolicy = verdictPolicy;
        this.artifactResolver = artifactResolver;
        this.ruleSetVersion = properties.analysis().ruleSetVersion();
    }

    @Transactional
    public CheckResponse check(CheckRequest request) {
        try {
            URI artifactUrl = urlPolicy.requireArtifactUrl(request.url());
            urlPolicy.requireCallbackUrl(request.callbackUrl());
            PackageIdentityPolicy.require(request.ecosystem(), request.packageName(), request.version(), artifactUrl);
            artifactResolver.requireListedHost(request.ecosystem(), artifactUrl);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }

        String name = PackageNames.normalize(request.ecosystem(), request.packageName());
        AnalysisJob job = jobRepository.insertIfAbsent(request.ecosystem(), name, request.version(), request.url());
        Optional<AnalysisResult> fresh = job.status() == JobStatus.DONE
                ? resultRepository.findByJobId(job.id()).filter(result -> ruleSetVersion.equals(result.ruleSetVersion()))
                : Optional.empty();
        if (fresh.isEmpty() && (job.status() == JobStatus.DONE || job.status() == JobStatus.FAILED)) {
            jobRepository.requeue(job.id(), request.url());
        }
        callbackRepository.register(job.id(), request.callbackUrl());

        if (fresh.isPresent()) {
            Decision decision = verdictPolicy.decide(job.ecosystem(), job.name(), job.version(), fresh.get().findings());
            return CheckResponse.done(decision.verdict(), decision.reason());
        }
        return CheckResponse.pending();
    }
}
