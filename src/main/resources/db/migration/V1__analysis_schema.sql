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


-- One row per package version to analyze. Lowercase ecosystem (npm, pypi, maven); Maven name is
-- "groupId:artifactId". Claimed by workers with SELECT ... FOR UPDATE SKIP LOCKED (AnalysisJobRepository).
CREATE TABLE analysis_job (
    id              UUID PRIMARY KEY,
    ecosystem       VARCHAR(10)  NOT NULL,
    name            VARCHAR(400) NOT NULL,
    version         VARCHAR(200) NOT NULL,
    artifact_url    TEXT         NOT NULL,
    status          VARCHAR(10)  NOT NULL,          -- PENDING / RUNNING / DONE / FAILED
    attempts        SMALLINT     NOT NULL DEFAULT 0,
    locked_by       TEXT,
    locked_until    TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_error      TEXT,
    queued_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),          -- reset on requeue
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_analysis_job_package UNIQUE (ecosystem, name, version)
);
CREATE INDEX idx_analysis_job_claim ON analysis_job (status, next_attempt_at);

-- Raw findings, before the behavior allowlist: the verdict is recomputed on read.
CREATE TABLE analysis_result (
    job_id           UUID PRIMARY KEY REFERENCES analysis_job (id) ON DELETE CASCADE,
    rule_set_version VARCHAR(50) NOT NULL,
    verdict          VARCHAR(10) NOT NULL,          -- ALLOWED / BLOCKED (at analysis time)
    score            INTEGER     NOT NULL,
    artifacts        JSONB       NOT NULL,          -- [{url, sha256, sizeBytes}]
    findings         JSONB       NOT NULL,          -- [{ruleId, severity, scanner, message, location}]
    finished_at      TIMESTAMPTZ NOT NULL
);

-- One row per SilicaProxy callback token waiting for this job's verdict. Delivered once the job is
-- DONE, then deleted.
CREATE TABLE pending_callback (
    id           BIGSERIAL PRIMARY KEY,
    job_id       UUID        NOT NULL REFERENCES analysis_job (id) ON DELETE CASCADE,
    callback_url TEXT        NOT NULL,
    attempts     SMALLINT    NOT NULL DEFAULT 0,
    next_try_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_pending_callback UNIQUE (job_id, callback_url)
);
CREATE INDEX idx_pending_callback_next_try ON pending_callback (next_try_at);
