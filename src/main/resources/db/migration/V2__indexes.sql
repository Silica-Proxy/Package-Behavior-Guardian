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


-- Indexes matched to the queries in AnalysisJobRepository / PendingCallbackRepository.
--
-- Plain CREATE INDEX (not CONCURRENTLY): Flyway runs this migration in a transaction, and the
-- tables are small when it runs. The active part of the queue (PENDING / RUNNING) stays small while
-- DONE / FAILED rows accumulate forever, so the queue indexes are partial: they only hold the rows
-- the hot queries look at, and their size does not grow with the history.

-- V1's (status, next_attempt_at) indexes every row, history included, and its low-cardinality
-- leading column only helps on the few active rows. It is replaced by the partial indexes below.
DROP INDEX idx_analysis_job_claim;

-- claim(): walks the active queue in queued_at order and stops at LIMIT (no sort).
-- countPending(): status IN ('PENDING', 'RUNNING') is exactly the index predicate.
-- oldestPendingQueuedAt(): first entry with status = 'PENDING' in queued_at order; status is
-- included so that filter is checked from the index.
CREATE INDEX idx_analysis_job_active_queued ON analysis_job (queued_at) INCLUDE (status)
    WHERE status IN ('PENDING', 'RUNNING');

-- claim(), PENDING branch: due jobs (next_attempt_at <= now()), for when most of the active queue
-- waits for a delayed retry and walking it in queued_at order would skip many rows.
CREATE INDEX idx_analysis_job_pending_due ON analysis_job (next_attempt_at)
    WHERE status = 'PENDING';

-- claim(), RUNNING branch, and failAbandoned() (run before every claim): expired leases
-- (locked_until < now()) among the RUNNING jobs only.
CREATE INDEX idx_analysis_job_running_lease ON analysis_job (locked_until)
    WHERE status = 'RUNNING';

-- pending_callback needs nothing new:
--  * job_id (the FK, used by the joins of claimDue() and deleteForFailedJobs() and by the
--    ON DELETE CASCADE from analysis_job) is already the leading column of uq_pending_callback
--    (job_id, callback_url), so a separate (job_id) index would be redundant;
--  * claimDue() filters and orders on next_try_at: idx_pending_callback_next_try (V1) serves it.
--    A partial index cannot express its other condition (the job being DONE lives in analysis_job)
--    and now() is not immutable, so there is no useful partial predicate. Callbacks are deleted once
--    delivered, so the table only ever holds waiting rows anyway.
