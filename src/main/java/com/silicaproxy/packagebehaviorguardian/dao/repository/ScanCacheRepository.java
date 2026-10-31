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

import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/** {@code scan_cache}: findings of one scanner on one file, by (sha256, scanner key, rule set). */
@Repository
@NullMarked
public class ScanCacheRepository {

    private static final TypeReference<List<Finding>> FINDINGS = new TypeReference<>() { };

    private final JdbcClient jdbcClient;
    private final ObjectMapper objectMapper;

    public ScanCacheRepository(JdbcClient jdbcClient, ObjectMapper objectMapper) {
        this.jdbcClient = jdbcClient;
        this.objectMapper = objectMapper;
    }

    public Optional<List<Finding>> find(String sha256, String scanner, String ruleSetVersion) {
        return jdbcClient.sql("""
                SELECT findings::text FROM scan_cache
                WHERE sha256 = :sha256 AND scanner = :scanner AND rule_set_version = :ruleSetVersion
                """)
                .param("sha256", sha256)
                .param("scanner", scanner)
                .param("ruleSetVersion", ruleSetVersion)
                .query(String.class)
                .optional()
                .map(findings -> objectMapper.readValue(findings, FINDINGS));
    }

    // Two jobs may scan the same file at the same time: the first one stored wins, both are equal.
    public void put(String sha256, String scanner, String ruleSetVersion, List<Finding> findings) {
        jdbcClient.sql("""
                INSERT INTO scan_cache (sha256, scanner, rule_set_version, findings)
                VALUES (:sha256, :scanner, :ruleSetVersion, CAST(:findings AS jsonb))
                ON CONFLICT DO NOTHING
                """)
                .param("sha256", sha256)
                .param("scanner", scanner)
                .param("ruleSetVersion", ruleSetVersion)
                .param("findings", objectMapper.writeValueAsString(findings))
                .update();
    }

    /** Deletes the entries of every other rule set and those created before {@code createdBefore}. */
    public int purge(String currentRuleSetVersion, Instant createdBefore) {
        return jdbcClient.sql("""
                DELETE FROM scan_cache WHERE rule_set_version <> :ruleSetVersion OR created_at < :createdBefore
                """)
                .param("ruleSetVersion", currentRuleSetVersion)
                .param("createdBefore", Timestamp.from(createdBefore))
                .update();
    }
}
