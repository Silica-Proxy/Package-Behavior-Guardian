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

import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.JobStatus;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * The analysis queue. Claiming is a single {@code UPDATE ... WHERE id IN (SELECT ... FOR UPDATE
 * SKIP LOCKED)} statement, so any number of workers (in any number of instances) can poll the same
 * table without a broker and without holding a transaction open during the analysis. A RUNNING job
 * whose lease expired (worker crash) becomes claimable again.
 */
@Repository
@NullMarked
public class AnalysisJobRepository {

    private static final String COLUMNS = "id, ecosystem, name, version, artifact_url, status, attempts, last_error, queued_at";

    private final JdbcClient jdbcClient;

    public AnalysisJobRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    /** Inserts a PENDING job unless one already exists for this package version; returns the job either way. */
    public AnalysisJob insertIfAbsent(String ecosystem, String name, String version, String artifactUrl) {
        jdbcClient.sql("""
                INSERT INTO analysis_job (id, ecosystem, name, version, artifact_url, status)
                VALUES (:id, :ecosystem, :name, :version, :artifactUrl, 'PENDING')
                ON CONFLICT (ecosystem, name, version) DO NOTHING
                """)
                .param("id", UUID.randomUUID())
                .param("ecosystem", ecosystem)
                .param("name", name)
                .param("version", version)
                .param("artifactUrl", artifactUrl)
                .update();
        return find(ecosystem, name, version).orElseThrow();
    }

    public Optional<AnalysisJob> find(String ecosystem, String name, String version) {
        return jdbcClient.sql("SELECT " + COLUMNS + " FROM analysis_job WHERE ecosystem = :ecosystem AND name = :name AND version = :version")
                .param("ecosystem", ecosystem)
                .param("name", name)
                .param("version", version)
                .query()
                .listOfRows()
                .stream()
                .findFirst()
                .map(AnalysisJobRepository::toJob);
    }

    public Optional<AnalysisJob> findById(UUID id) {
        return jdbcClient.sql("SELECT " + COLUMNS + " FROM analysis_job WHERE id = :id")
                .param("id", id)
                .query()
                .listOfRows()
                .stream()
                .findFirst()
                .map(AnalysisJobRepository::toJob);
    }

    /** Puts a FAILED or outdated DONE job back in the queue, with a fresh attempt budget. */
    public void requeue(UUID id, String artifactUrl) {
        jdbcClient.sql("""
                UPDATE analysis_job
                SET status = 'PENDING', attempts = 0, next_attempt_at = now(), locked_by = NULL,
                    locked_until = NULL, last_error = NULL, artifact_url = :artifactUrl, queued_at = now(), updated_at = now()
                WHERE id = :id AND status IN ('DONE', 'FAILED')
                """)
                .param("id", id)
                .param("artifactUrl", artifactUrl)
                .update();
    }

    public List<AnalysisJob> claim(String workerId, int limit, Duration lease, int maxAttempts) {
        return jdbcClient.sql("""
                UPDATE analysis_job
                SET status = 'RUNNING', locked_by = :workerId, locked_until = now() + make_interval(secs => :leaseSeconds),
                    attempts = attempts + 1, updated_at = now()
                WHERE id IN (
                    SELECT id FROM analysis_job
                    WHERE attempts < :maxAttempts
                      AND ((status = 'PENDING' AND next_attempt_at <= now())
                           OR (status = 'RUNNING' AND locked_until < now()))
                    ORDER BY queued_at
                    LIMIT :limit
                    FOR UPDATE SKIP LOCKED)
                RETURNING
                """ + COLUMNS)
                .param("workerId", workerId)
                .param("leaseSeconds", lease.toSeconds())
                .param("maxAttempts", maxAttempts)
                .param("limit", limit)
                .query()
                .listOfRows()
                .stream()
                .map(AnalysisJobRepository::toJob)
                .toList();
    }

    /** A RUNNING job whose lease expired with no attempt left (its worker kept crashing) is given up. */
    public int failAbandoned(int maxAttempts) {
        return jdbcClient.sql("""
                UPDATE analysis_job
                SET status = 'FAILED', locked_by = NULL, locked_until = NULL, updated_at = now(),
                    last_error = COALESCE(last_error, 'worker lease expired')
                WHERE status = 'RUNNING' AND locked_until < now() AND attempts >= :maxAttempts
                """)
                .param("maxAttempts", maxAttempts)
                .update();
    }

    // Every transition of a RUNNING job is fenced on its lease holder: a worker whose lease expired
    // (its job was claimed again elsewhere) must not overwrite the new holder's state.

    /** False when this worker no longer holds the job. */
    public boolean markDone(UUID id, String workerId) {
        return jdbcClient.sql("""
                UPDATE analysis_job
                SET status = 'DONE', locked_by = NULL, locked_until = NULL, last_error = NULL, updated_at = now()
                WHERE id = :id AND status = 'RUNNING' AND locked_by = :workerId
                """)
                .param("id", id)
                .param("workerId", workerId)
                .update() == 1;
    }

    /** Extends the lease of the jobs this worker is still analyzing. */
    public void renewLeases(List<UUID> ids, String workerId, Duration lease) {
        if (ids.isEmpty()) {
            return;
        }
        jdbcClient.sql("""
                UPDATE analysis_job SET locked_until = now() + make_interval(secs => :leaseSeconds)
                WHERE id IN (:ids) AND status = 'RUNNING' AND locked_by = :workerId
                """)
                .param("ids", ids)
                .param("workerId", workerId)
                .param("leaseSeconds", lease.toSeconds())
                .update();
    }

    /** On shutdown: hands the jobs back to the queue without spending an attempt. */
    public void release(List<UUID> ids, String workerId) {
        if (ids.isEmpty()) {
            return;
        }
        jdbcClient.sql("""
                UPDATE analysis_job
                SET status = 'PENDING', attempts = GREATEST(attempts - 1, 0), locked_by = NULL, locked_until = NULL,
                    next_attempt_at = now(), updated_at = now()
                WHERE id IN (:ids) AND status = 'RUNNING' AND locked_by = :workerId
                """)
                .param("ids", ids)
                .param("workerId", workerId)
                .update();
    }

    /** Back to PENDING after {@code retryDelay}, or FAILED once the attempt budget is spent. */
    public void markFailed(UUID id, String workerId, String error, boolean retry, Duration retryDelay) {
        jdbcClient.sql("""
                UPDATE analysis_job
                SET status = :status, locked_by = NULL, locked_until = NULL, last_error = :error,
                    next_attempt_at = now() + make_interval(secs => :delaySeconds), updated_at = now()
                WHERE id = :id AND status = 'RUNNING' AND locked_by = :workerId
                """)
                .param("id", id)
                .param("workerId", workerId)
                .param("status", (retry ? JobStatus.PENDING : JobStatus.FAILED).name())
                .param("error", error)
                .param("delaySeconds", retryDelay.toSeconds())
                .update();
    }

    public long countPending() {
        return jdbcClient.sql("SELECT count(*) FROM analysis_job WHERE status IN ('PENDING', 'RUNNING')")
                .query(Long.class)
                .single();
    }

    public Optional<Instant> oldestPendingQueuedAt() {
        return jdbcClient.sql("SELECT min(queued_at) FROM analysis_job WHERE status = 'PENDING'")
                .query(Timestamp.class)
                .optional()
                .map(Timestamp::toInstant);
    }

    private static AnalysisJob toJob(Map<String, Object> row) {
        return new AnalysisJob(
                (UUID) row.get("id"),
                (String) row.get("ecosystem"),
                (String) row.get("name"),
                (String) row.get("version"),
                (String) row.get("artifact_url"),
                JobStatus.valueOf((String) row.get("status")),
                ((Number) row.get("attempts")).intValue(),
                (String) row.get("last_error"),
                ((Timestamp) row.get("queued_at")).toInstant());
    }
}
