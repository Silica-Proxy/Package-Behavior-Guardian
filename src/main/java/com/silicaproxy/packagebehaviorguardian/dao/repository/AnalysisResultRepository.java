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

import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisResult;
import com.silicaproxy.packagebehaviorguardian.model.entity.ArtifactInfo;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/** {@code analysis_result}: one row per job, replaced when a job is re-analyzed under a newer rule set. */
@Repository
@NullMarked
public class AnalysisResultRepository {

    private static final TypeReference<List<ArtifactInfo>> ARTIFACTS = new TypeReference<>() { };
    private static final TypeReference<List<Finding>> FINDINGS = new TypeReference<>() { };

    private final JdbcClient jdbcClient;
    private final ObjectMapper objectMapper;

    public AnalysisResultRepository(JdbcClient jdbcClient, ObjectMapper objectMapper) {
        this.jdbcClient = jdbcClient;
        this.objectMapper = objectMapper;
    }

    public void upsert(AnalysisResult result) {
        jdbcClient.sql("""
                INSERT INTO analysis_result
                    (job_id, rule_set_version, artifacts, findings, finished_at)
                VALUES (:jobId, :ruleSetVersion,
                        CAST(:artifacts AS jsonb), CAST(:findings AS jsonb), :finishedAt)
                ON CONFLICT (job_id) DO UPDATE SET
                    rule_set_version = EXCLUDED.rule_set_version,
                    artifacts = EXCLUDED.artifacts, findings = EXCLUDED.findings, finished_at = EXCLUDED.finished_at
                """)
                .param("jobId", result.jobId())
                .param("ruleSetVersion", result.ruleSetVersion())
                .param("artifacts", objectMapper.writeValueAsString(result.artifacts()))
                .param("findings", objectMapper.writeValueAsString(result.findings()))
                .param("finishedAt", Timestamp.from(result.finishedAt()))
                .update();
    }

    public Optional<AnalysisResult> findByJobId(UUID jobId) {
        return jdbcClient.sql("""
                SELECT job_id, rule_set_version,
                       artifacts::text AS artifacts, findings::text AS findings, finished_at
                FROM analysis_result WHERE job_id = :jobId
                """)
                .param("jobId", jobId)
                .query()
                .listOfRows()
                .stream()
                .findFirst()
                .map(this::toResult);
    }

    private AnalysisResult toResult(Map<String, Object> row) {
        return new AnalysisResult(
                (UUID) row.get("job_id"),
                (String) row.get("rule_set_version"),
                objectMapper.readValue((String) row.get("artifacts"), ARTIFACTS),
                objectMapper.readValue((String) row.get("findings"), FINDINGS),
                ((Timestamp) row.get("finished_at")).toInstant());
    }
}
