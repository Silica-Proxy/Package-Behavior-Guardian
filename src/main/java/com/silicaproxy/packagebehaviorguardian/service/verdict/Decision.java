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


package com.silicaproxy.packagebehaviorguardian.service.verdict;

import com.silicaproxy.packagebehaviorguardian.model.dto.Verdict;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import java.util.List;
import org.jspecify.annotations.NullMarked;

/** Outcome of {@link VerdictPolicy}: {@code counted} findings made the verdict, {@code allowlisted} ones were set aside. */
@NullMarked
public record Decision(Verdict verdict, int score, String reason, List<Finding> counted, List<Finding> allowlisted) {

    public Decision {
        counted = List.copyOf(counted);
        allowlisted = List.copyOf(allowlisted);
    }

    /**
     * The rules that made a BLOCKED verdict, distinct and in order: the CRITICAL ones when there are,
     * else every counted rule that scored (LOW findings never do). Empty for ALLOWED.
     */
    public List<String> blockingRules() {
        if (verdict != Verdict.BLOCKED) {
            return List.of();
        }
        List<String> critical = counted.stream().filter(finding -> finding.severity() == Severity.CRITICAL)
                .map(Finding::ruleId).distinct().toList();
        return critical.isEmpty()
                ? counted.stream().filter(finding -> finding.severity() != Severity.LOW).map(Finding::ruleId).distinct().toList()
                : critical;
    }
}
