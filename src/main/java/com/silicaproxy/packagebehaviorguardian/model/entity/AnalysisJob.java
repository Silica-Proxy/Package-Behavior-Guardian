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
import java.util.UUID;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * Row of {@code analysis_job}: one package version to analyze, unique per (ecosystem, name,
 * version). {@code artifactUrl} is the URL of the first request; the analysis itself covers the
 * whole version (every PyPI file, the main Maven jar), see {@code ReleaseArtifactResolver}. {@code
 * queuedAt} is when the job last entered the queue (insert or requeue).
 */
@NullMarked
public record AnalysisJob(
        UUID id,
        String ecosystem,
        String name,
        String version,
        String artifactUrl,
        JobStatus status,
        int attempts,
        @Nullable String lastError,
        Instant queuedAt) {
}
