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
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * The analysis queue. Claiming is a single {@code WITH picked AS (SELECT ... FOR UPDATE SKIP LOCKED)
 * UPDATE ... FROM picked} statement, so any number of workers (in any number of instances) can poll the same
 * table without a broker and without holding a transaction open during the analysis. A RUNNING job
 * whose lease expired (worker crash) becomes claimable again; the claim reports it, so that the lost
 * attempt is audited.
 */
@Repository
@NullMarked
public class AnalysisJobRepository {

    private static final String COLUMNS = "id, ecosystem, name, version, artifact_url, status, attempts, last_error, queued_at";
    // COLUMNS of analysis_job aliased j, for statements that join it.
    private static final String QUALIFIED_COLUMNS = "j.id, j.ecosystem, j.name, j.version, j.artifact_url, j.status, "
            + "j.attempts, j.last_error, j.queued_at";

    private final JdbcClient jdbcClient;

    public AnalysisJobRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    /**
     * Inserts a PENDING job unless one already exists for this package version; returns the job either way,
     * locked until the end of the transaction: its status cannot change (a worker finishing it waits) while
     * the caller decides from it. One statement -- the upsert takes the row lock itself -- also stamps
     * {@code last_checked_at}, so {@link #purgeFinished} can neither delete the job between the insert and
     * the read nor once the check has seen it.
     */
    public AnalysisJob insertIfAbsent(String ecosystem, String name, String version, String artifactUrl) {
        return jdbcClient.sql("""
                INSERT INTO analysis_job (id, ecosystem, name, version, artifact_url, status)
                VALUES (:id, :ecosystem, :name, :version, :artifactUrl, 'PENDING')
                ON CONFLICT (ecosystem, name, version) DO UPDATE SET last_checked_at = now()
                RETURNING
                """ + COLUMNS)
                .param("id", UUID.randomUUID())
                .param("ecosystem", ecosystem)
                .param("name", name)
                .param("version", version)
                .param("artifactUrl", artifactUrl)
                .query()
                .listOfRows()
                .stream()
                .findFirst()
                .map(AnalysisJobRepository::toJob)
                .orElseThrow();
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

    /**
     * An attempt whose worker vanished: its lease expired before the attempt ended. {@code job} is the
     * job as the statement left it, {@code attempt} the number of the lost attempt, {@code workerId} the
     * worker that held it.
     */
    public record LostLease(AnalysisJob job, int attempt, @Nullable String workerId) { }

    /** The jobs claimed, and those of them whose previous attempt was lost (lease expired). */
    public record Claim(List<AnalysisJob> jobs, List<LostLease> expiredLeases) {

        public Claim {
            jobs = List.copyOf(jobs);
            expiredLeases = List.copyOf(expiredLeases);
        }
    }

    public Claim claim(String workerId, int limit, Duration lease, int maxAttempts) {
        List<Map<String, Object>> rows = jdbcClient.sql("""
                WITH picked AS (
                    SELECT id, status AS previous_status, locked_by AS previous_worker FROM analysis_job
                    WHERE attempts < :maxAttempts
                      AND ((status = 'PENDING' AND next_attempt_at <= now())
                           OR (status = 'RUNNING' AND locked_until < now()))
                    ORDER BY queued_at
                    LIMIT :limit
                    FOR UPDATE SKIP LOCKED)
                UPDATE analysis_job j
                SET status = 'RUNNING', locked_by = :workerId, locked_until = now() + make_interval(secs => :leaseSeconds),
                    attempts = j.attempts + 1, updated_at = now()
                FROM picked p WHERE j.id = p.id
                RETURNING p.previous_status, p.previous_worker,
                """ + QUALIFIED_COLUMNS)
                .param("workerId", workerId)
                .param("leaseSeconds", lease.toSeconds())
                .param("maxAttempts", maxAttempts)
                .param("limit", limit)
                .query()
                .listOfRows();
        List<AnalysisJob> jobs = rows.stream().map(AnalysisJobRepository::toJob).toList();
        List<LostLease> expired = rows.stream()
                .filter(row -> JobStatus.RUNNING.name().equals(row.get("previous_status")))
                .map(row -> {
                    AnalysisJob job = toJob(row);
                    return new LostLease(job, job.attempts() - 1, (String) row.get("previous_worker"));
                })
                .toList();
        return new Claim(jobs, expired);
    }

    /**
     * A RUNNING job whose lease expired with no attempt left (its worker kept crashing) is given up.
     * Returns the jobs given up, for the caller to audit (ABANDONED): the audit is not written by this
     * statement, so that a failing audit write never keeps the queue from moving.
     */
    public List<LostLease> failAbandoned(int maxAttempts) {
        return jdbcClient.sql("""
                WITH abandoned AS (
                    SELECT id, locked_by FROM analysis_job
                    WHERE status = 'RUNNING' AND locked_until < now() AND attempts >= :maxAttempts
                    FOR UPDATE SKIP LOCKED)
                UPDATE analysis_job j
                SET status = 'FAILED', locked_by = NULL, locked_until = NULL, updated_at = now(),
                    last_error = COALESCE(j.last_error, 'worker lease expired')
                FROM abandoned a WHERE j.id = a.id
                RETURNING a.locked_by AS previous_worker,
                """ + QUALIFIED_COLUMNS)
                .param("maxAttempts", maxAttempts)
                .query()
                .listOfRows()
                .stream()
                .map(row -> {
                    AnalysisJob job = toJob(row);
                    return new LostLease(job, job.attempts(), (String) row.get("previous_worker"));
                })
                .toList();
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

    /** Back to PENDING after {@code retryDelay}, or FAILED once the attempts are spent. False when this worker lost the job. */
    public boolean markFailed(UUID id, String workerId, String error, boolean retry, Duration retryDelay) {
        return jdbcClient.sql("""
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
                .update() == 1;
    }

    /**
     * Deletes, by batches of {@code batchSize}, the DONE and FAILED jobs neither updated nor checked for
     * {@code retention} -- their result and callbacks go with them (ON DELETE CASCADE) -- but never one
     * with a callback still waiting. Rows locked by a check or a worker are skipped, and the conditions
     * are re-evaluated on the locked row, so a job checked meanwhile survives. Returns the jobs deleted.
     */
    public int purgeFinished(Duration retention, int batchSize) {
        int total = 0;
        int deleted;
        do {
            deleted = jdbcClient.sql("""
                    DELETE FROM analysis_job WHERE id IN (
                        SELECT j.id FROM analysis_job j
                        WHERE j.status IN ('DONE', 'FAILED')
                          AND j.updated_at < now() - make_interval(secs => :retentionSeconds)
                          AND j.last_checked_at < now() - make_interval(secs => :retentionSeconds)
                          AND NOT EXISTS (SELECT 1 FROM pending_callback pc WHERE pc.job_id = j.id)
                        LIMIT :limit
                        FOR UPDATE SKIP LOCKED)
                    """)
                    .param("retentionSeconds", retention.toSeconds())
                    .param("limit", batchSize)
                    .update();
            total += deleted;
        } while (deleted == batchSize);
        return total;
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
