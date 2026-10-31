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
package com.silicaproxy.packagebehaviorguardian.dao.repository;

import com.silicaproxy.packagebehaviorguardian.model.dto.Verdict;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisAudit;
import com.silicaproxy.packagebehaviorguardian.model.entity.CheckAudit;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import tools.jackson.databind.ObjectMapper;

/**
 * {@code analysis_audit} and {@code check_audit}: append-only, rows are only inserted, and deleted
 * once past their retention. Not tied to {@code analysis_job}, so they outlive its purge.
 */
@Repository
@NullMarked
public class AuditRepository {

    private final JdbcClient jdbcClient;
    private final ObjectMapper objectMapper;

    public AuditRepository(JdbcClient jdbcClient, ObjectMapper objectMapper) {
        this.jdbcClient = jdbcClient;
        this.objectMapper = objectMapper;
    }

    public void insert(AnalysisAudit audit) {
        Verdict verdict = audit.verdict();
        jdbcClient.sql("""
                INSERT INTO analysis_audit
                    (job_id, attempt, worker_id, outcome, ecosystem, name, version, artifact_url, verdict, score, reason,
                     blocking_rules, findings, allowlisted, artifacts, error, queued_at, started_at, finished_at,
                     wait_ms, run_ms, resolve_ms, download_ms, scan_ms, rule_set_version, high_weight, medium_weight,
                     block_threshold)
                VALUES (:jobId, :attempt, :workerId, :outcome, :ecosystem, :name, :version, :artifactUrl, :verdict,
                        :score, :reason, ARRAY(SELECT jsonb_array_elements_text(CAST(:blockingRules AS jsonb))), CAST(:findings AS jsonb),
                        CAST(:allowlisted AS jsonb), CAST(:artifacts AS jsonb), :error, :queuedAt, :startedAt,
                        :finishedAt, :waitMs, :runMs, :resolveMs, :downloadMs, :scanMs, :ruleSetVersion, :highWeight,
                        :mediumWeight, :blockThreshold)
                """)
                .param("jobId", audit.jobId())
                .param("attempt", audit.attempt())
                .param("workerId", audit.workerId())
                .param("outcome", audit.outcome().name())
                .param("ecosystem", audit.ecosystem())
                .param("name", audit.name())
                .param("version", audit.version())
                .param("artifactUrl", audit.artifactUrl())
                .param("verdict", verdict == null ? null : verdict.name())
                .param("score", audit.score())
                .param("reason", audit.reason())
                .param("blockingRules", objectMapper.writeValueAsString(audit.blockingRules()))
                .param("findings", objectMapper.writeValueAsString(audit.findings()))
                .param("allowlisted", objectMapper.writeValueAsString(audit.allowlisted()))
                .param("artifacts", objectMapper.writeValueAsString(audit.artifacts()))
                .param("error", audit.error())
                .param("queuedAt", timestamp(audit.queuedAt()))
                .param("startedAt", timestamp(audit.startedAt()))
                .param("finishedAt", timestamp(audit.finishedAt()))
                .param("waitMs", audit.waitMs())
                .param("runMs", audit.runMs())
                .param("resolveMs", audit.resolveMs())
                .param("downloadMs", audit.downloadMs())
                .param("scanMs", audit.scanMs())
                .param("ruleSetVersion", audit.ruleSetVersion())
                .param("highWeight", audit.highWeight())
                .param("mediumWeight", audit.mediumWeight())
                .param("blockThreshold", audit.blockThreshold())
                .update();
    }

    public void insert(CheckAudit audit) {
        Verdict verdict = audit.verdict();
        jdbcClient.sql("""
                INSERT INTO check_audit
                    (received_at, duration_ms, ecosystem, requested_name, name, version, artifact_url, callback_host,
                     client_address, http_status, response_status, verdict, reason, job_id)
                VALUES (:receivedAt, :durationMs, :ecosystem, :requestedName, :name, :version, :artifactUrl,
                        :callbackHost, :clientAddress, :httpStatus, :responseStatus, :verdict, :reason, :jobId)
                """)
                .param("receivedAt", timestamp(audit.receivedAt()))
                .param("durationMs", audit.durationMs())
                .param("ecosystem", audit.ecosystem())
                .param("requestedName", audit.requestedName())
                .param("name", audit.name())
                .param("version", audit.version())
                .param("artifactUrl", audit.artifactUrl())
                .param("callbackHost", audit.callbackHost())
                .param("clientAddress", audit.clientAddress())
                .param("httpStatus", audit.httpStatus())
                .param("responseStatus", audit.responseStatus().name())
                .param("verdict", verdict == null ? null : verdict.name())
                .param("reason", audit.reason())
                .param("jobId", audit.jobId())
                .update();
    }

    /** Deletes, by batches of {@code batchSize}, the analysis audit rows finished more than {@code retention} ago. */
    public int purgeAnalyses(Duration retention, int batchSize) {
        return purge("DELETE FROM analysis_audit WHERE id IN (SELECT id FROM analysis_audit"
                + " WHERE finished_at < now() - make_interval(secs => :retentionSeconds) LIMIT :limit)", retention, batchSize);
    }

    /** Deletes, by batches of {@code batchSize}, the check audit rows received more than {@code retention} ago. */
    public int purgeChecks(Duration retention, int batchSize) {
        return purge("DELETE FROM check_audit WHERE id IN (SELECT id FROM check_audit"
                + " WHERE received_at < now() - make_interval(secs => :retentionSeconds) LIMIT :limit)", retention, batchSize);
    }

    private int purge(String sql, Duration retention, int batchSize) {
        int total = 0;
        int deleted;
        do {
            deleted = jdbcClient.sql(sql)
                    .param("retentionSeconds", retention.toSeconds())
                    .param("limit", batchSize)
                    .update();
            total += deleted;
        } while (deleted == batchSize);
        return total;
    }

    private static @Nullable Timestamp timestamp(@Nullable Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }
}
