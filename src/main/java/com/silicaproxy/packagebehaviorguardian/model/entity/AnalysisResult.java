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

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.jspecify.annotations.NullMarked;

/**
 * Row of {@code analysis_result}. {@code findings} are the raw scanner findings, before the
 * allowlist is applied: the verdict is recomputed from them on every read, so an allowlist change
 * applies to versions already analyzed, and so does a change of the verdict scale. The decision
 * taken at analysis time is kept in {@code analysis_audit}.
 */
@NullMarked
public record AnalysisResult(
        UUID jobId,
        String ruleSetVersion,
        List<ArtifactInfo> artifacts,
        List<Finding> findings,
        Instant finishedAt) {

    public AnalysisResult {
        artifacts = List.copyOf(artifacts);
        findings = List.copyOf(findings);
    }
}
