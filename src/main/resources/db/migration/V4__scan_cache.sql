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


-- Findings of one scanner on one downloaded file, keyed by the file's SHA-256: the same file (shared
-- across versions, re-analyzed after a requeue, same wheel in several packages) is not scanned again.
-- Only complete scans are stored: a failed scan is never cached. The file's local name is replaced by
-- a placeholder in the stored findings and put back on reuse (ScanCache), so a hit stays correct for
-- another package. scanner is the scanner's cache key: its name plus whatever else changes its
-- results (e.g. "guarddog:npm"). Rows of another rule set, and rows older than
-- analysis.scan-cache-max-age-days, are purged periodically.
CREATE TABLE scan_cache (
    sha256           VARCHAR(64)  NOT NULL,
    scanner          VARCHAR(100) NOT NULL,
    rule_set_version VARCHAR(50)  NOT NULL,
    findings         JSONB        NOT NULL,          -- [{ruleId, severity, scanner, message, location}]
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (sha256, scanner, rule_set_version)
);
CREATE INDEX idx_scan_cache_created_at ON scan_cache (created_at);
