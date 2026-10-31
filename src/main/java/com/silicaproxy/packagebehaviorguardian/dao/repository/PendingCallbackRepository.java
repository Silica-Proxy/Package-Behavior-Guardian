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

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@code pending_callback}: SilicaProxy callback URLs waiting for a verdict. Claiming pushes
 * {@code next_try_at} forward by a lease and increments {@code attempts} in the same statement, so a
 * callback is never sent twice in parallel, and one whose sender crashed is retried after the lease.
 */
@Repository
@NullMarked
public class PendingCallbackRepository {

    private final JdbcClient jdbcClient;

    public PendingCallbackRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public record ClaimedCallback(long id, UUID jobId, String callbackUrl, int attempts) {
    }

    /**
     * Records a callback to send once the job is DONE. A callback already waiting for the same URL gets a
     * fresh attempt budget: the new request must not inherit the attempts spent for an earlier one.
     */
    public void register(UUID jobId, String callbackUrl) {
        jdbcClient.sql("""
                INSERT INTO pending_callback (job_id, callback_url) VALUES (:jobId, :callbackUrl)
                ON CONFLICT (job_id, callback_url) DO UPDATE SET attempts = 0
                """)
                .param("jobId", jobId)
                .param("callbackUrl", callbackUrl)
                .update();
    }

    /** Claims callbacks that are due and whose job is DONE. */
    public List<ClaimedCallback> claimDue(int limit, Duration lease) {
        return jdbcClient.sql("""
                UPDATE pending_callback
                SET attempts = attempts + 1, next_try_at = now() + make_interval(secs => :leaseSeconds)
                WHERE id IN (
                    SELECT pc.id FROM pending_callback pc
                    JOIN analysis_job j ON j.id = pc.job_id
                    WHERE j.status = 'DONE' AND pc.next_try_at <= now()
                    ORDER BY pc.next_try_at
                    LIMIT :limit
                    FOR UPDATE OF pc SKIP LOCKED)
                RETURNING id, job_id, callback_url, attempts
                """)
                .param("leaseSeconds", lease.toSeconds())
                .param("limit", limit)
                .query((rs, rowNum) -> new ClaimedCallback(
                        rs.getLong("id"), rs.getObject("job_id", UUID.class), rs.getString("callback_url"), rs.getInt("attempts")))
                .list();
    }

    public void delete(long id) {
        jdbcClient.sql("DELETE FROM pending_callback WHERE id = :id").param("id", id).update();
    }

    /**
     * Drops a callback whose attempts are spent, unless {@link #register} gave it a fresh budget since it was
     * claimed: it is then retried when its claim lease expires.
     */
    public void giveUp(long id, int claimedAttempts) {
        jdbcClient.sql("DELETE FROM pending_callback WHERE id = :id AND attempts = :attempts")
                .param("id", id)
                .param("attempts", claimedAttempts)
                .update();
    }

    public void reschedule(long id, Duration delay) {
        jdbcClient.sql("UPDATE pending_callback SET next_try_at = now() + make_interval(secs => :delaySeconds) WHERE id = :id")
                .param("id", id)
                .param("delaySeconds", delay.toSeconds())
                .update();
    }

    /** A job that failed for good will never produce a verdict: its waiting callbacks are dropped (SilicaProxy times them out). */
    public int deleteForFailedJobs() {
        return jdbcClient.sql("""
                DELETE FROM pending_callback pc USING analysis_job j
                WHERE j.id = pc.job_id AND j.status = 'FAILED'
                """)
                .update();
    }
}
