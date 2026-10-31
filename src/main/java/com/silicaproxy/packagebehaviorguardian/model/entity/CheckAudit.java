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
import java.util.UUID;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * One row of {@code check_audit}: a {@code POST /v1/check} and what it was answered. Only the host
 * of the callback URL is kept, the rest of it is a secret token.
 */
@NullMarked
public record CheckAudit(
        Instant receivedAt,
        long durationMs,
        String ecosystem,
        String requestedName,
        @Nullable String name,
        String version,
        String artifactUrl,
        @Nullable String callbackHost,
        @Nullable String clientAddress,
        int httpStatus,
        ResponseStatus responseStatus,
        @Nullable Verdict verdict,
        @Nullable String reason,
        @Nullable UUID jobId) {

    /** What the caller got back. */
    public enum ResponseStatus {
        /** 202: the version is being analyzed, the verdict comes by callback. */
        PENDING,
        /** 200: verdict already known, in the body (and sent to the callback). */
        DONE,
        /** 400: refused (URL, package identity or host not allowed). */
        REJECTED,
        /** 5xx: the service failed. */
        ERROR
    }
}
