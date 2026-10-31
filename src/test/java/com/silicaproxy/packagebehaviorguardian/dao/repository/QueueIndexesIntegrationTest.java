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

import static org.assertj.core.api.Assertions.assertThat;

import com.silicaproxy.packagebehaviorguardian.BaseIntegrationTest;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

/**
 * The queue queries can use the V2 indexes. Tables are tiny in tests, so the planner would pick a
 * sequential scan on its own: it is disabled for the (rolled back) test transaction, which only
 * checks that an index matching the query exists. Plain EXPLAIN: nothing is executed.
 */
@Transactional
class QueueIndexesIntegrationTest extends BaseIntegrationTest {

    private static final Logger LOG = LoggerFactory.getLogger(QueueIndexesIntegrationTest.class);

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void disableSeqScan() {
        jdbcTemplate.execute("SET LOCAL enable_seqscan = off");
    }

    private String explain(String sql) {
        List<String> lines = jdbcTemplate.queryForList("EXPLAIN " + sql, String.class);
        String plan = String.join("\n", lines);
        LOG.info("Plan for:\n{}\n{}", sql.strip(), plan);
        return plan;
    }

    @Test
    void claimUsesTheActiveQueueIndexes() {
        String plan = explain("""
                UPDATE analysis_job
                SET status = 'RUNNING', locked_by = 'w', locked_until = now() + make_interval(secs => 300),
                    attempts = attempts + 1, updated_at = now()
                WHERE id IN (
                    SELECT id FROM analysis_job
                    WHERE attempts < 3
                      AND ((status = 'PENDING' AND next_attempt_at <= now())
                           OR (status = 'RUNNING' AND locked_until < now()))
                    ORDER BY queued_at
                    LIMIT 10
                    FOR UPDATE SKIP LOCKED)
                """);
        assertThat(plan).containsAnyOf("idx_analysis_job_active_queued", "idx_analysis_job_pending_due");
    }

    @Test
    void failAbandonedUsesTheRunningLeaseIndex() {
        String plan = explain("""
                UPDATE analysis_job SET status = 'FAILED', locked_by = NULL, locked_until = NULL
                WHERE status = 'RUNNING' AND locked_until < now() AND attempts >= 3
                """);
        assertThat(plan).contains("idx_analysis_job_running_lease");
    }

    @Test
    void monitoringQueriesUseTheActiveQueueIndex() {
        assertThat(explain("SELECT count(*) FROM analysis_job WHERE status IN ('PENDING', 'RUNNING')"))
                .contains("idx_analysis_job_active_queued");
        // Either partial index restricts the scan to active rows (pending_due holds exactly the PENDING ones).
        assertThat(explain("SELECT min(queued_at) FROM analysis_job WHERE status = 'PENDING'"))
                .containsAnyOf("idx_analysis_job_active_queued", "idx_analysis_job_pending_due");
    }

    @Test
    void callbackQueriesUseTheirIndexes() {
        // claimDue: by next_try_at, or driven from the DONE jobs through the job_id-leading unique index.
        assertThat(explain("""
                SELECT pc.id FROM pending_callback pc
                JOIN analysis_job j ON j.id = pc.job_id
                WHERE j.status = 'DONE' AND pc.next_try_at <= now()
                ORDER BY pc.next_try_at
                LIMIT 10
                FOR UPDATE OF pc SKIP LOCKED
                """)).containsAnyOf("idx_pending_callback_next_try", "uq_pending_callback");
        assertThat(explain("""
                DELETE FROM pending_callback pc USING analysis_job j
                WHERE j.id = pc.job_id AND j.status = 'FAILED'
                """)).containsAnyOf("uq_pending_callback", "analysis_job_pkey");
    }
}
