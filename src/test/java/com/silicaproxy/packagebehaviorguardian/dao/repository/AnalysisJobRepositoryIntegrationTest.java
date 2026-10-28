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
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.JobStatus;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/** Lease fencing: a worker whose lease was taken over must not overwrite the new holder's state. */
class AnalysisJobRepositoryIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private AnalysisJobRepository repository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // Inserted as RUNNING for "worker-a" directly: the application's own worker must not claim it.
    private UUID runningJob(String workerId) {
        UUID id = UUID.randomUUID();
        jdbcTemplate.update("""
                INSERT INTO analysis_job (id, ecosystem, name, version, artifact_url, status, attempts, locked_by, locked_until)
                VALUES (?, 'npm', ?, '1.0.0', 'http://localhost/x.tgz', 'RUNNING', 1, ?, now() + interval '10 minutes')
                """, id, "fencing-" + id, workerId);
        return id;
    }

    @Test
    void onlyTheLeaseHolderCanFinishTheJob() {
        UUID id = runningJob("worker-a");

        assertThat(repository.markDone(id, "worker-b")).isFalse();
        repository.markFailed(id, "worker-b", "stale", false, Duration.ZERO);
        assertThat(repository.findById(id)).map(AnalysisJob::status).contains(JobStatus.RUNNING);

        assertThat(repository.markDone(id, "worker-a")).isTrue();
        assertThat(repository.findById(id)).map(AnalysisJob::status).contains(JobStatus.DONE);
    }

    @Test
    void releasingAJobOnShutdownGivesBackTheAttempt() {
        UUID id = runningJob("worker-a");

        repository.release(List.of(id), "worker-b");
        assertThat(repository.findById(id)).map(AnalysisJob::status).contains(JobStatus.RUNNING);

        repository.release(List.of(id), "worker-a");
        assertThat(repository.findById(id)).hasValueSatisfying(job -> {
            assertThat(job.status()).isEqualTo(JobStatus.PENDING);
            assertThat(job.attempts()).isZero();
        });
    }
}
