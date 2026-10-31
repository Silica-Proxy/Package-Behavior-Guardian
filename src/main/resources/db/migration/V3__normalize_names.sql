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


-- Last POST /v1/check of the version: the purge (JobPurger) keeps a job checked recently, and the
-- check stamping it in the same upsert that locks the row closes the race with the purge. Existing
-- rows start from their last update.
ALTER TABLE analysis_job ADD COLUMN last_checked_at TIMESTAMPTZ NOT NULL DEFAULT now();
UPDATE analysis_job SET last_checked_at = updated_at;
CREATE INDEX idx_analysis_job_purge ON analysis_job (updated_at) WHERE status IN ('DONE', 'FAILED');

-- PyPI names in their PEP 503 form (PackageNames): lowercase, runs of '-', '_', '.' -> '-'. npm and
-- Maven names are case-sensitive in registry paths and stay as they are. Spellings of one version
-- collapse into one job: the one in flight (RUNNING, then PENDING) is kept, else the latest updated;
-- the waiting callbacks of the others move to it, then the others are deleted with their results.
CREATE TEMPORARY TABLE pypi_job_name AS
SELECT id,
       version,
       lower(regexp_replace(name, '[-_.]+', '-', 'g')) AS normalized,
       row_number() OVER (
           PARTITION BY lower(regexp_replace(name, '[-_.]+', '-', 'g')), version
           ORDER BY CASE status WHEN 'RUNNING' THEN 0 WHEN 'PENDING' THEN 1 WHEN 'DONE' THEN 2 ELSE 3 END,
                    updated_at DESC, id) AS rank
FROM analysis_job
WHERE ecosystem = 'pypi';

INSERT INTO pending_callback (job_id, callback_url, attempts, next_try_at, created_at)
SELECT kept.id, pc.callback_url, pc.attempts, pc.next_try_at, pc.created_at
FROM pending_callback pc
JOIN pypi_job_name dropped ON dropped.id = pc.job_id AND dropped.rank > 1
JOIN pypi_job_name kept ON kept.normalized = dropped.normalized AND kept.version = dropped.version AND kept.rank = 1
ON CONFLICT (job_id, callback_url) DO NOTHING;

DELETE FROM analysis_job j USING pypi_job_name n WHERE j.id = n.id AND n.rank > 1;

UPDATE analysis_job j SET name = n.normalized
FROM pypi_job_name n
WHERE j.id = n.id AND j.name <> n.normalized;

DROP TABLE pypi_job_name;
