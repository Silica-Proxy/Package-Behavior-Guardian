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

import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.AllowlistEntry;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@code allowlist_entry} and {@code allowlist_sync}: the GitOps allowlist, replaced as a whole by
 * each synchronization, and the state of the last one.
 */
@Repository
@NullMarked
public class AllowlistRepository {

    /** An entry, and the repository file it was read from. */
    public record StoredEntry(AllowlistEntry entry, String sourceFile) { }

    /**
     * The last synchronization: {@code generation} grows with each successful one; {@code syncedAt}
     * is when the last one succeeded, {@code lastError} the error of the last attempt (null if it
     * succeeded).
     */
    public record SyncState(long generation, @Nullable String revision, int entries, int skipped,
            @Nullable Instant syncedAt, @Nullable Instant lastAttemptAt, @Nullable String lastError) { }

    private final JdbcClient jdbcClient;

    public AllowlistRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    /** The outcome of {@link #replace}: the generation in force, and whether the entries changed. */
    public record Replaced(long generation, boolean changed) { }

    /**
     * Replaces every entry and bumps the generation, in one transaction -- unless the entries (and the
     * number skipped) are those already stored: then only the commit and the time of the sync are
     * recorded, so that the instances do not reload for nothing. The sync row is locked first, so two
     * synchronizations (scheduled and forced, or two instances past a lost lock) never interleave.
     */
    @Transactional
    public Replaced replace(List<StoredEntry> entries, @Nullable String revision, int skipped) {
        jdbcClient.sql("SELECT id FROM allowlist_sync WHERE id = 1 FOR UPDATE").query().listOfRows();
        SyncState current = state();
        if (current.syncedAt() != null && current.skipped() == skipped && storedEntries().equals(entries)) {
            jdbcClient.sql("""
                    UPDATE allowlist_sync SET revision = :revision, synced_at = now(), last_attempt_at = now(), last_error = NULL
                    WHERE id = 1
                    """)
                    .param("revision", revision)
                    .update();
            return new Replaced(current.generation(), false);
        }
        jdbcClient.sql("DELETE FROM allowlist_entry").update();
        for (StoredEntry stored : entries) {
            AllowlistEntry entry = stored.entry();
            jdbcClient.sql("""
                    INSERT INTO allowlist_entry (ecosystem, name, version, rule_id, detail, reason, source_file)
                    VALUES (:ecosystem, :name, :version, :ruleId, :detail, :reason, :sourceFile)
                    """)
                    .param("ecosystem", entry.ecosystem())
                    .param("name", entry.name())
                    .param("version", entry.version())
                    .param("ruleId", entry.ruleId())
                    .param("detail", entry.detail())
                    .param("reason", entry.reason())
                    .param("sourceFile", stored.sourceFile())
                    .update();
        }
        long generation = jdbcClient.sql("""
                UPDATE allowlist_sync
                SET generation = generation + 1, revision = :revision, entries = :entries, skipped = :skipped,
                    synced_at = now(), last_attempt_at = now(), last_error = NULL
                WHERE id = 1
                RETURNING generation
                """)
                .param("revision", revision)
                .param("entries", entries.size())
                .param("skipped", skipped)
                .query(Long.class)
                .single();
        return new Replaced(generation, true);
    }

    private List<StoredEntry> storedEntries() {
        return jdbcClient.sql("""
                SELECT ecosystem, name, version, rule_id, detail, reason, source_file FROM allowlist_entry ORDER BY id
                """)
                .query((rs, rowNum) -> new StoredEntry(new AllowlistEntry(rs.getString("ecosystem"), rs.getString("name"),
                        rs.getString("version"), rs.getString("rule_id"), rs.getString("detail"), rs.getString("reason")),
                        rs.getString("source_file")))
                .list();
    }

    /** Records a failed synchronization: the entries of the last successful one stay in force. */
    public void recordFailure(String error) {
        jdbcClient.sql("UPDATE allowlist_sync SET last_attempt_at = now(), last_error = :error WHERE id = 1")
                .param("error", error)
                .update();
    }

    public SyncState state() {
        Map<String, Object> row = jdbcClient.sql("""
                SELECT generation, revision, entries, skipped, synced_at, last_attempt_at, last_error
                FROM allowlist_sync WHERE id = 1
                """)
                .query()
                .singleRow();
        return new SyncState(((Number) row.get("generation")).longValue(), (String) row.get("revision"),
                ((Number) row.get("entries")).intValue(), ((Number) row.get("skipped")).intValue(),
                instant(row.get("synced_at")), instant(row.get("last_attempt_at")), (String) row.get("last_error"));
    }

    public List<AllowlistEntry> entries() {
        return jdbcClient.sql("SELECT ecosystem, name, version, rule_id, detail, reason FROM allowlist_entry ORDER BY id")
                .query((rs, rowNum) -> new AllowlistEntry(rs.getString("ecosystem"), rs.getString("name"),
                        rs.getString("version"), rs.getString("rule_id"), rs.getString("detail"), rs.getString("reason")))
                .list();
    }

    private static @Nullable Instant instant(@Nullable Object value) {
        return value instanceof Timestamp timestamp ? timestamp.toInstant() : null;
    }
}
