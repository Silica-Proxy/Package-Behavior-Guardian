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
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

class PendingCallbackRepositoryIntegrationTest extends BaseIntegrationTest {

    private static final String URL = "http://localhost/callback/token";

    @Autowired
    private PendingCallbackRepository repository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // RUNNING for another worker: the application's dispatcher only claims callbacks of DONE jobs.
    private UUID runningJob() {
        UUID id = UUID.randomUUID();
        jdbcTemplate.update("""
                INSERT INTO analysis_job (id, ecosystem, name, version, artifact_url, status, attempts, locked_by, locked_until)
                VALUES (?, 'npm', ?, '1.0.0', 'http://localhost/x.tgz', 'RUNNING', 1, 'worker-a', now() + interval '10 minutes')
                """, id, "callback-" + id);
        return id;
    }

    private Integer attempts(UUID jobId) {
        return jdbcTemplate.queryForObject("SELECT attempts FROM pending_callback WHERE job_id = ?", Integer.class, jobId);
    }

    private long callbackId(UUID jobId) {
        return jdbcTemplate.queryForObject("SELECT id FROM pending_callback WHERE job_id = ?", Long.class, jobId);
    }

    @Test
    void aNewRequestGetsAFreshAttemptBudget() {
        UUID jobId = runningJob();
        repository.register(jobId, URL);
        jdbcTemplate.update("UPDATE pending_callback SET attempts = 10 WHERE job_id = ?", jobId);

        repository.register(jobId, URL);

        assertThat(attempts(jobId)).isZero();
    }

    @Test
    void givingUpSparesACallbackRegisteredAgainSinceItsClaim() {
        UUID jobId = runningJob();
        repository.register(jobId, URL);
        jdbcTemplate.update("UPDATE pending_callback SET attempts = 11 WHERE job_id = ?", jobId);
        long id = callbackId(jobId);

        repository.register(jobId, URL);
        repository.giveUp(id, 11);
        assertThat(attempts(jobId)).isZero();

        repository.giveUp(id, 0);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM pending_callback WHERE job_id = ?", Integer.class, jobId))
                .isZero();
    }
}
