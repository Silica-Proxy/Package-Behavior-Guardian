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


-- Append-only audit trail. No foreign key to analysis_job: an audit row outlives the purge of its
-- job, and has its own retention (retention.analysis-audit-days / check-audit-days).

-- One row per analysis attempt that ended: DONE (verdict stored), RETRY (failed, queued again),
-- FAILED (attempt budget spent) or ABANDONED (lease expired with no attempt left).
CREATE TABLE analysis_audit (
    id               BIGSERIAL PRIMARY KEY,
    job_id           UUID         NOT NULL,
    attempt          SMALLINT     NOT NULL,
    worker_id        TEXT,
    outcome          VARCHAR(10)  NOT NULL,
    ecosystem        VARCHAR(10)  NOT NULL,
    name             VARCHAR(400) NOT NULL,
    version          VARCHAR(200) NOT NULL,
    artifact_url     TEXT         NOT NULL,
    verdict          VARCHAR(10),                   -- ALLOWED / BLOCKED, at decision time (DONE only)
    score            INTEGER,
    reason           TEXT,                          -- exactly what SilicaProxy was sent
    blocking_rules   TEXT[]       NOT NULL DEFAULT '{}',
    findings         JSONB        NOT NULL DEFAULT '[]',   -- counted findings
    allowlisted      JSONB        NOT NULL DEFAULT '[]',   -- findings set aside by the allowlist
    artifacts        JSONB        NOT NULL DEFAULT '[]',   -- [{url, sha256, sizeBytes}]
    error            TEXT,
    queued_at        TIMESTAMPTZ  NOT NULL,
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ  NOT NULL,
    wait_ms          BIGINT,                        -- started_at - queued_at
    run_ms           BIGINT,                        -- finished_at - started_at
    resolve_ms       BIGINT,
    download_ms      BIGINT,
    scan_ms          BIGINT,
    rule_set_version VARCHAR(50),
    high_weight      INTEGER,
    medium_weight    INTEGER,
    block_threshold  INTEGER
);
CREATE INDEX idx_analysis_audit_finished_at ON analysis_audit (finished_at);
CREATE INDEX idx_analysis_audit_package ON analysis_audit (ecosystem, name, version);

-- One row per POST /v1/check that reached the service with a well-formed body (authenticated).
CREATE TABLE check_audit (
    id              BIGSERIAL PRIMARY KEY,
    received_at     TIMESTAMPTZ  NOT NULL,
    duration_ms     BIGINT       NOT NULL,
    ecosystem       VARCHAR(10)  NOT NULL,
    requested_name  VARCHAR(400) NOT NULL,          -- as sent
    name            VARCHAR(400),                   -- canonical (null when refused)
    version         VARCHAR(200) NOT NULL,
    artifact_url    TEXT         NOT NULL,
    callback_host   TEXT,                           -- host[:port] only: the callback URL holds a secret token
    client_address  TEXT,
    http_status     SMALLINT     NOT NULL,
    response_status VARCHAR(10)  NOT NULL,          -- PENDING / DONE / REJECTED / ERROR
    verdict         VARCHAR(10),
    reason          TEXT,
    job_id          UUID
);
CREATE INDEX idx_check_audit_received_at ON check_audit (received_at);
CREATE INDEX idx_check_audit_package ON check_audit (ecosystem, name, version);
