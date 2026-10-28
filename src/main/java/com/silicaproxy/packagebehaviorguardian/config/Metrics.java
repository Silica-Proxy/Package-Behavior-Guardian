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


package com.silicaproxy.packagebehaviorguardian.config;

import org.jspecify.annotations.NullMarked;

/**
 * Single source of truth for every custom Micrometer metric name and tag key used across
 * packagebehaviorguardian, so a metric's spelling is never duplicated at each call/assertion site.
 */
@NullMarked
public final class Metrics {

    private Metrics() {
    }

    public static final String TAG_ECOSYSTEM = "ecosystem";
    public static final String TAG_VERDICT = "verdict";
    public static final String TAG_PASS = "pass";
    public static final String TAG_RULE_ID = "rule_id";
    public static final String TAG_SCANNER = "scanner";
    public static final String TAG_RESULT = "result";

    public static final String PASS_STATIC = "static";

    public static final String QUEUE_DEPTH_METRIC = "packagebehaviorguardian.queue.depth";
    public static final String QUEUE_WAIT_METRIC = "packagebehaviorguardian.queue.wait";
    public static final String ANALYSIS_DURATION_METRIC = "packagebehaviorguardian.analysis.duration";
    public static final String ANALYSIS_VERDICT_METRIC = "packagebehaviorguardian.analysis.verdict";
    public static final String ANALYSIS_FAILURES_METRIC = "packagebehaviorguardian.analysis.failures";
    public static final String FINDING_COUNT_METRIC = "packagebehaviorguardian.finding.count";
    public static final String CALLBACK_METRIC = "packagebehaviorguardian.callback";
    public static final String CALLBACK_FAILURES_METRIC = "packagebehaviorguardian.callback.failures";

    public static final String RESULT_DELIVERED = "DELIVERED";
    public static final String RESULT_GONE = "GONE";
    public static final String RESULT_RETRY = "RETRY";
}
