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


-- The verdict is recomputed from the raw findings on every read, with the current allowlist and the
-- configurable scale (analysis.high-weight / medium-weight / block-threshold): the verdict and score
-- stored at analysis time went stale and were never read. The decision taken at analysis time, with
-- the scale used, is in analysis_audit.
ALTER TABLE analysis_result DROP COLUMN verdict, DROP COLUMN score;
