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
package com.silicaproxy.packagebehaviorguardian.controller;

import static org.assertj.core.api.Assertions.assertThat;

import com.silicaproxy.packagebehaviorguardian.BaseIntegrationTest;
import com.silicaproxy.packagebehaviorguardian.FakeRegistry;
import com.silicaproxy.packagebehaviorguardian.TestJars;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.service.audit.AuditService;
import com.silicaproxy.packagebehaviorguardian.service.queue.JobPurger;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;

/** The audit trail: every ended analysis attempt and every check leaves a row, purged on its own retention. */
class AuditIntegrationTest extends BaseIntegrationTest {

    private static FakeRegistry registry;

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private AnalysisJobRepository jobRepository;

    @Autowired
    private JobPurger jobPurger;

    @Autowired
    private AuditService auditService;

    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeAll
    static void startRegistry() throws IOException {
        registry = new FakeRegistry();
        String dir = "/maven2/com/evil/audited/1.0/";
        registry.serve(dir + "audited-1.0.pom", "<project/>".getBytes(StandardCharsets.UTF_8));
        registry.serve(dir + "audited-1.0.jar", TestJars.jar(TestJars.entries(
                "com/evil/Init.class", TestJars.classWithExecInStaticInitializer("com/evil/Init"))));
        String broken = "/maven2/com/evil/audit-broken/1.0/";
        registry.serve(broken + "audit-broken-1.0.pom", "<project/>".getBytes(StandardCharsets.UTF_8));
        registry.serve(broken + "audit-broken-1.0.jar", TestJars.jar(TestJars.entries(
                "com/evil/Init.class", TestJars.classWithExecInStaticInitializer("com/evil/Init"))));
    }

    @AfterAll
    static void stopRegistry() {
        registry.close();
    }

    private HttpResponse<String> check(String name, String version, String ecosystem, String url, String callbackUrl)
            throws IOException, InterruptedException {
        String body = """
                {"packageName": "%s", "version": "%s", "ecosystem": "%s", "url": "%s", "callbackUrl": "%s"}
                """.formatted(name, version, ecosystem, url, callbackUrl);
        return httpClient.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v1/check"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String newCallbackUrl() {
        return registry.url("/callback/" + UUID.randomUUID());
    }

    private static <T> T await(Supplier<T> query, Predicate<T> done) throws InterruptedException {
        Instant deadline = Instant.now().plus(Duration.ofSeconds(30));
        T value = query.get();
        while (!done.test(value) && Instant.now().isBefore(deadline)) {
            Thread.sleep(100);
            value = query.get();
        }
        return value;
    }

    private List<Map<String, Object>> analyses(String ecosystem, String name, String version) {
        return jdbcTemplate.queryForList("""
                SELECT outcome, attempt, worker_id, verdict, score, reason, array_to_string(blocking_rules, ',') AS rules,
                       findings::text AS findings, artifacts::text AS artifacts, error, started_at, wait_ms, run_ms,
                       resolve_ms, download_ms, scan_ms, rule_set_version, block_threshold
                FROM analysis_audit WHERE ecosystem = ? AND name = ? AND version = ? ORDER BY id
                """, ecosystem, name, version);
    }

    private List<Map<String, Object>> checks(String requestedName, String version) {
        return jdbcTemplate.queryForList("""
                SELECT name, http_status, response_status, verdict, reason, job_id, callback_host, client_address, duration_ms
                FROM check_audit WHERE requested_name = ? AND version = ? ORDER BY id
                """, requestedName, version);
    }

    @Test
    void aBlockedAnalysisAndBothChecksAreAudited() throws IOException, InterruptedException {
        String pomUrl = registry.url("/maven2/com/evil/audited/1.0/audited-1.0.pom");
        assertThat(check("com.evil:audited", "1.0", "maven", pomUrl, newCallbackUrl()).statusCode()).isEqualTo(202);

        List<Map<String, Object>> analyses = await(() -> analyses("maven", "com.evil:audited", "1.0"), rows -> !rows.isEmpty());
        assertThat(analyses).hasSize(1);
        Map<String, Object> analysis = analyses.get(0);
        assertThat(analysis).containsEntry("outcome", "DONE").containsEntry("verdict", "BLOCKED")
                .containsEntry("rules", "JVM-001").containsEntry("rule_set_version", "2").containsEntry("block_threshold", 60)
                .containsEntry("attempt", 1);
        assertThat((String) analysis.get("reason")).startsWith("BLOCKED by JVM-001");
        assertThat((String) analysis.get("findings")).contains("JVM-001");
        assertThat((String) analysis.get("artifacts")).contains("audited-1.0.jar").contains("sha256");
        assertThat(analysis.get("worker_id")).asString().startsWith("worker-");
        for (String column : List.of("started_at", "wait_ms", "run_ms", "resolve_ms", "download_ms", "scan_ms")) {
            assertThat(analysis.get(column)).as(column).isNotNull();
        }

        // The verdict is stored: the next check is answered at once.
        assertThat(check("com.evil:audited", "1.0", "maven", pomUrl, newCallbackUrl()).statusCode()).isEqualTo(200);
        List<Map<String, Object>> checks = checks("com.evil:audited", "1.0");
        assertThat(checks).extracting(row -> row.get("response_status")).startsWith("PENDING").endsWith("DONE");
        Map<String, Object> first = checks.get(0);
        Map<String, Object> last = checks.get(checks.size() - 1);
        assertThat(first).containsEntry("http_status", 202).containsEntry("name", "com.evil:audited");
        assertThat(first.get("job_id")).isNotNull().isEqualTo(last.get("job_id"));
        assertThat(first.get("callback_host")).asString().startsWith("localhost:");
        assertThat(first.get("client_address")).isNotNull();
        assertThat(last).containsEntry("http_status", 200).containsEntry("verdict", "BLOCKED");
        assertThat((String) last.get("reason")).startsWith("BLOCKED by JVM-001");
    }

    @Test
    void aRefusedCheckIsAudited() throws IOException, InterruptedException {
        HttpResponse<String> response = check("audit-refused", "1.0.0", "npm",
                registry.url("/npm/audit-refused/-/audit-refused-1.0.0.tgz"), "http://169.254.169.254/latest/meta-data");

        assertThat(response.statusCode()).isEqualTo(400);
        List<Map<String, Object>> checks = checks("audit-refused", "1.0.0");
        assertThat(checks).hasSize(1);
        assertThat(checks.get(0)).containsEntry("response_status", "REJECTED").containsEntry("http_status", 400)
                .containsEntry("callback_host", "169.254.169.254").containsEntry("name", null).containsEntry("job_id", null);
        assertThat((String) checks.get(0).get("reason")).contains("The callback URL host is not allowed");
    }

    @Test
    void eachFailedAttemptIsAudited() throws IOException, InterruptedException {
        check("audit-ghost", "1.0.0", "npm", registry.url("/npm/audit-ghost/-/audit-ghost-1.0.0.tgz"), newCallbackUrl());

        List<Map<String, Object>> analyses = await(() -> analyses("npm", "audit-ghost", "1.0.0"), rows -> rows.size() >= 3);
        assertThat(analyses).extracting(row -> row.get("outcome")).containsExactly("RETRY", "RETRY", "FAILED");
        assertThat(analyses).extracting(row -> row.get("attempt")).containsExactly(1, 2, 3);
        assertThat(analyses).allSatisfy(row -> {
            assertThat((String) row.get("error")).contains("Not found");
            assertThat(row.get("verdict")).isNull();
            assertThat(row.get("run_ms")).isNotNull();
        });
    }

    @Test
    void anAbandonedJobIsAudited() throws InterruptedException {
        UUID id = UUID.randomUUID();
        jdbcTemplate.update("""
                INSERT INTO analysis_job (id, ecosystem, name, version, artifact_url, status, attempts, locked_by, locked_until)
                VALUES (?, 'npm', 'audit-abandoned', '1.0.0', 'http://localhost/x.tgz', 'RUNNING', 99, 'worker-gone',
                        now() - interval '1 minute')
                """, id);

        // The scheduled worker (max-attempts 3) gives it up too: whichever does it writes the row.
        auditService.recordAbandoned(jobRepository.failAbandoned(99));

        List<Map<String, Object>> rows = await(() -> jdbcTemplate.queryForList(
                "SELECT outcome, attempt, worker_id, error, rule_set_version FROM analysis_audit WHERE job_id = ?", id),
                found -> !found.isEmpty());
        assertThat(rows).singleElement().satisfies(row -> assertThat(row)
                .containsEntry("outcome", "ABANDONED").containsEntry("attempt", 99)
                .containsEntry("worker_id", "worker-gone").containsEntry("error", "worker lease expired")
                .containsEntry("rule_set_version", "2"));
    }

    @Test
    void anAttemptWhoseLeaseExpiredIsAuditedWhenTheJobIsClaimedAgain() throws InterruptedException {
        UUID id = UUID.randomUUID();
        jdbcTemplate.update("""
                INSERT INTO analysis_job (id, ecosystem, name, version, artifact_url, status, attempts, locked_by, locked_until)
                VALUES (?, 'npm', 'audit-expired', '1.0.0', 'http://localhost/x.tgz', 'RUNNING', 1, 'worker-crashed',
                        now() - interval '1 minute')
                """, id);

        List<Map<String, Object>> rows = await(() -> jdbcTemplate.queryForList(
                "SELECT outcome, attempt, worker_id, error FROM analysis_audit WHERE job_id = ? ORDER BY id", id),
                found -> !found.isEmpty());
        assertThat(rows.get(0)).containsEntry("outcome", "EXPIRED").containsEntry("attempt", 1)
                .containsEntry("worker_id", "worker-crashed").containsEntry("error", "worker lease expired");
    }

    @Test
    void aFailingAuditWriteDoesNotCostTheVerdict() throws IOException, InterruptedException {
        // Only this package's audit rows are refused; NOT VALID leaves the existing rows alone.
        jdbcTemplate.execute("ALTER TABLE analysis_audit ADD CONSTRAINT test_audit_broken"
                + " CHECK (name <> 'com.evil:audit-broken') NOT VALID");
        try {
            String pomUrl = registry.url("/maven2/com/evil/audit-broken/1.0/audit-broken-1.0.pom");
            assertThat(check("com.evil:audit-broken", "1.0", "maven", pomUrl, newCallbackUrl()).statusCode()).isEqualTo(202);

            String status = await(() -> jdbcTemplate.queryForObject(
                    "SELECT status FROM analysis_job WHERE ecosystem = 'maven' AND name = 'com.evil:audit-broken'", String.class),
                    "DONE"::equals);
            assertThat(status).isEqualTo("DONE");
            assertThat(analyses("maven", "com.evil:audit-broken", "1.0")).isEmpty();

            HttpResponse<String> again = check("com.evil:audit-broken", "1.0", "maven", pomUrl, newCallbackUrl());
            assertThat(again.statusCode()).isEqualTo(200);
            assertThat(again.body()).contains("BLOCKED");
        } finally {
            jdbcTemplate.execute("ALTER TABLE analysis_audit DROP CONSTRAINT test_audit_broken");
        }
    }

    @Test
    void auditRowsArePurgedOnTheirOwnRetentionUnderAShedLock() {
        UUID job = UUID.randomUUID();
        String insertAnalysis = """
                INSERT INTO analysis_audit (job_id, attempt, outcome, ecosystem, name, version, artifact_url, queued_at,
                                            finished_at)
                VALUES (?, 1, 'DONE', 'npm', ?, '1.0.0', 'http://localhost/x.tgz', now(), now() - make_interval(days => ?))
                """;
        jdbcTemplate.update(insertAnalysis, job, "audit-old", 400);
        jdbcTemplate.update(insertAnalysis, job, "audit-recent", 10);
        String insertCheck = """
                INSERT INTO check_audit (received_at, duration_ms, ecosystem, requested_name, version, artifact_url,
                                         http_status, response_status)
                VALUES (now() - make_interval(days => ?), 1, 'npm', ?, '1.0.0', 'http://localhost/x.tgz', 202, 'PENDING')
                """;
        jdbcTemplate.update(insertCheck, 400, "audit-old");
        jdbcTemplate.update(insertCheck, 10, "audit-recent");

        jobPurger.purge();

        assertThat(jdbcTemplate.queryForList("SELECT name FROM analysis_audit WHERE name LIKE 'audit-%' AND job_id = ?",
                String.class, job)).containsExactly("audit-recent");
        assertThat(jdbcTemplate.queryForList(
                "SELECT requested_name FROM check_audit WHERE requested_name IN ('audit-old', 'audit-recent')", String.class))
                .containsExactly("audit-recent");
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM shedlock WHERE name = 'pbg-purge'", Long.class)).isOne();
    }
}
