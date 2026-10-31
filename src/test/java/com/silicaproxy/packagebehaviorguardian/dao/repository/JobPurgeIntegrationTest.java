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
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/** Retention: only finished jobs neither updated nor checked for the retention period go, with their results. */
class JobPurgeIntegrationTest extends BaseIntegrationTest {

    private static final Duration RETENTION = Duration.ofDays(90);

    @Autowired
    private AnalysisJobRepository repository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // attempts = 99 and a far lease keep the application's own worker from claiming PENDING/RUNNING rows.
    private UUID job(String status, int updatedDaysAgo, int checkedDaysAgo) {
        UUID id = UUID.randomUUID();
        jdbcTemplate.update("""
                INSERT INTO analysis_job (id, ecosystem, name, version, artifact_url, status, attempts, locked_until,
                                          updated_at, last_checked_at)
                VALUES (?, 'npm', ?, '1.0.0', 'http://localhost/x.tgz', ?, 99, now() + interval '1 day',
                        now() - make_interval(days => ?), now() - make_interval(days => ?))
                """, id, "purge-" + id, status, updatedDaysAgo, checkedDaysAgo);
        if ("DONE".equals(status)) {
            jdbcTemplate.update("""
                    INSERT INTO analysis_result (job_id, rule_set_version, artifacts, findings, finished_at)
                    VALUES (?, '1', '[]', '[]', now() - make_interval(days => ?))
                    """, id, updatedDaysAgo);
        }
        return id;
    }

    private boolean exists(UUID id) {
        return jdbcTemplate.queryForObject("SELECT count(*) FROM analysis_job WHERE id = ?", Long.class, id) == 1;
    }

    private long results(UUID id) {
        return jdbcTemplate.queryForObject("SELECT count(*) FROM analysis_result WHERE job_id = ?", Long.class, id);
    }

    @Test
    void oldFinishedJobsArePurgedWithTheirResultsAndNothingElse() {
        UUID oldDone = job("DONE", 100, 100);
        UUID oldFailed = job("FAILED", 120, 120);
        UUID oldDone2 = job("DONE", 95, 95);
        UUID recentDone = job("DONE", 10, 10);
        UUID recentlyChecked = job("DONE", 100, 5);
        UUID oldPending = job("PENDING", 100, 100);
        UUID oldRunning = job("RUNNING", 100, 100);
        UUID waitingCallback = job("DONE", 100, 100);
        // Not due before tomorrow: the application's dispatcher leaves it alone during the test.
        jdbcTemplate.update("INSERT INTO pending_callback (job_id, callback_url, next_try_at) VALUES (?, ?, now() + interval '1 day')",
                waitingCallback, "http://localhost/callback/" + waitingCallback);

        // A batch smaller than the number of eligible jobs: the purge loops until none is left.
        assertThat(repository.purgeFinished(RETENTION, 2)).isGreaterThanOrEqualTo(3);

        assertThat(exists(oldDone)).isFalse();
        assertThat(results(oldDone)).isZero();
        assertThat(exists(oldFailed)).isFalse();
        assertThat(exists(oldDone2)).isFalse();
        assertThat(exists(recentDone)).isTrue();
        assertThat(results(recentDone)).isOne();
        assertThat(exists(recentlyChecked)).isTrue();
        assertThat(exists(oldPending)).isTrue();
        assertThat(exists(oldRunning)).isTrue();
        assertThat(exists(waitingCallback)).isTrue();
        assertThat(results(waitingCallback)).isOne();
    }

    @Test
    void aCheckKeepsAnOldJobFromBeingPurged() {
        UUID old = job("DONE", 100, 100);
        String name = jdbcTemplate.queryForObject("SELECT name FROM analysis_job WHERE id = ?", String.class, old);

        assertThat(repository.insertIfAbsent("npm", name, "1.0.0", "http://localhost/x.tgz").id()).isEqualTo(old);
        repository.purgeFinished(RETENTION, 100);

        assertThat(exists(old)).isTrue();
    }
}
