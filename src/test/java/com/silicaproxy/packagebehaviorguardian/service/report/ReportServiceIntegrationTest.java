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


package com.silicaproxy.packagebehaviorguardian.service.report;

import static org.assertj.core.api.Assertions.assertThat;

import com.silicaproxy.packagebehaviorguardian.BaseIntegrationTest;
import com.silicaproxy.packagebehaviorguardian.model.dto.Verdict;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;

class ReportServiceIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private ReportService reportService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Value("${packagebehaviorguardian.analysis.rule-set-version}")
    private String ruleSetVersion;

    // RUNNING jobs are held by another worker so that the application's own worker leaves them alone.
    private String job(String status, String ruleSetVersionOfResult) {
        UUID id = UUID.randomUUID();
        String name = "report-" + id;
        jdbcTemplate.update("""
                INSERT INTO analysis_job (id, ecosystem, name, version, artifact_url, status, attempts, locked_by, locked_until)
                VALUES (?, 'npm', ?, '1.0.0', 'http://localhost/x.tgz', ?, 1, 'worker-a', now() + interval '10 minutes')
                """, id, name, status);
        jdbcTemplate.update("""
                INSERT INTO analysis_result (job_id, rule_set_version, artifacts, findings, finished_at)
                VALUES (?, ?, '[]'::jsonb, '[]'::jsonb, now())
                """, id, ruleSetVersionOfResult);
        return name;
    }

    @Test
    void aRequeuedJobDoesNotServeItsPreviousVerdict() {
        String name = job("RUNNING", ruleSetVersion);

        assertThat(reportService.report("npm", name, "1.0.0")).hasValueSatisfying(report -> {
            assertThat(report.status()).isEqualTo("RUNNING");
            assertThat(report.verdict()).isNull();
            assertThat(report.reason()).isNull();
        });
    }

    @Test
    void aResultOfAnOlderRuleSetIsReportedOutdated() {
        String name = job("DONE", "0");

        assertThat(reportService.report("npm", name, "1.0.0")).hasValueSatisfying(report -> {
            assertThat(report.status()).isEqualTo(ReportService.OUTDATED);
            assertThat(report.verdict()).isNull();
            assertThat(report.ruleSetVersion()).isEqualTo("0");
        });
    }

    @Test
    void aDoneJobOfTheCurrentRuleSetHasItsVerdict() {
        String name = job("DONE", ruleSetVersion);

        assertThat(reportService.report("npm", name, "1.0.0")).hasValueSatisfying(report -> {
            assertThat(report.status()).isEqualTo("DONE");
            assertThat(report.verdict()).isEqualTo(Verdict.ALLOWED);
            assertThat(report.reason()).contains("rule set " + ruleSetVersion);
        });
    }
}
