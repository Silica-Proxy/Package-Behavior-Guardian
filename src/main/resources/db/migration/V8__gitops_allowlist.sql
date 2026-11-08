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


-- GitOps allowlist: the entries read from the Git repository (packagebehaviorguardian.gitops), replaced
-- as a whole by each synchronization (one instance at a time, ShedLock). Every instance reloads them
-- when allowlist_sync.generation changes.
CREATE TABLE allowlist_entry (
    id          BIGSERIAL    PRIMARY KEY,
    ecosystem   VARCHAR(10)  NOT NULL,
    name        VARCHAR(400) NOT NULL,
    version     VARCHAR(200),
    rule_id     VARCHAR(100),
    detail      TEXT,
    reason      TEXT         NOT NULL,
    source_file VARCHAR(100) NOT NULL
);

-- One row: the state of the last synchronization. generation is bumped by every successful one; a
-- failed one only records its error and keeps the entries of the last success.
CREATE TABLE allowlist_sync (
    id              SMALLINT    PRIMARY KEY CHECK (id = 1),
    generation      BIGINT      NOT NULL,
    revision        VARCHAR(64),
    entries         INT         NOT NULL,
    skipped         INT         NOT NULL,
    synced_at       TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    last_error      TEXT
);

INSERT INTO allowlist_sync (id, generation, entries, skipped) VALUES (1, 0, 0, 0);
