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
package com.silicaproxy.packagebehaviorguardian.model.entity;

import com.silicaproxy.packagebehaviorguardian.model.dto.Verdict;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * One row of {@code analysis_audit}: an analysis attempt that ended. The verdict, score, reason and
 * blocking rules are those of the decision taken then, with the rule set and the scale used for it.
 */
@NullMarked
public record AnalysisAudit(
        UUID jobId,
        int attempt,
        @Nullable String workerId,
        Outcome outcome,
        String ecosystem,
        String name,
        String version,
        String artifactUrl,
        @Nullable Verdict verdict,
        @Nullable Integer score,
        @Nullable String reason,
        List<String> blockingRules,
        List<Finding> findings,
        List<Finding> allowlisted,
        List<ArtifactInfo> artifacts,
        @Nullable String error,
        Instant queuedAt,
        @Nullable Instant startedAt,
        Instant finishedAt,
        @Nullable Long waitMs,
        @Nullable Long runMs,
        @Nullable Long resolveMs,
        @Nullable Long downloadMs,
        @Nullable Long scanMs,
        @Nullable String ruleSetVersion,
        @Nullable Integer highWeight,
        @Nullable Integer mediumWeight,
        @Nullable Integer blockThreshold) {

    public AnalysisAudit {
        blockingRules = List.copyOf(blockingRules);
        findings = List.copyOf(findings);
        allowlisted = List.copyOf(allowlisted);
        artifacts = List.copyOf(artifacts);
    }

    /** How the attempt ended. */
    public enum Outcome {
        /** A verdict was stored and is sent to SilicaProxy. */
        DONE,
        /** Failed; the job is queued again. */
        RETRY,
        /** Failed with no attempt left: no verdict (SilicaProxy's fail-open/fail-closed policy applies). */
        FAILED,
        /** Its worker vanished (lease expired); the job was claimed again for a new attempt. */
        EXPIRED,
        /** Its worker vanished (lease expired) with no attempt left. */
        ABANDONED
    }
}
