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
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.AllowlistEntry;
import com.silicaproxy.packagebehaviorguardian.service.report.ReportLinks;
import com.silicaproxy.packagebehaviorguardian.service.statics.Texts;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

/**
 * Findings to verdict. Findings covered by the configured allowlist are set aside first. Then one
 * CRITICAL blocks; otherwise HIGH (40) and MEDIUM (15) findings add up -- each rule once, at its
 * highest severity, so that one behavior repeated in ten methods does not outweigh two distinct
 * behaviors -- and a score of 60 or more blocks with "manual review required". Two verdicts only:
 * the grey zone is a BLOCKED with the report link, released through a SilicaProxy GitOps policy or
 * an allowlist entry here. The reason quotes the rule ID and the description of the first
 * CRITICAL finding -- this service's or the scanner's rule description, clipped and stripped of
 * control characters (a location, which may come from the package, is never quoted).
 */
@Component
@NullMarked
public class VerdictPolicy {

    static final int HIGH_WEIGHT = 40;
    static final int MEDIUM_WEIGHT = 15;
    static final int BLOCK_THRESHOLD = 60;

    private final List<AllowlistEntry> allowlist;
    private final String ruleSetVersion;
    private final ReportLinks reportLinks;

    public VerdictPolicy(PackageBehaviorGuardianProperties properties, ReportLinks reportLinks) {
        this.allowlist = List.copyOf(properties.allowlist());
        this.ruleSetVersion = properties.analysis().ruleSetVersion();
        this.reportLinks = reportLinks;
    }

    public Decision decide(String ecosystem, String name, String version, List<Finding> findings) {
        List<Finding> counted = new ArrayList<>();
        List<Finding> allowlisted = new ArrayList<>();
        for (Finding finding : findings) {
            (allowlist.stream().anyMatch(entry -> entry.covers(ecosystem, name, version, finding)) ? allowlisted : counted).add(finding);
        }
        String reportSuffix = reportLinks.suffix(ecosystem, name, version);

        Optional<Finding> critical = counted.stream().filter(finding -> finding.severity() == Severity.CRITICAL).findFirst();
        int score = score(counted);
        if (critical.isPresent()) {
            Finding finding = critical.get();
            return new Decision(Verdict.BLOCKED, score,
                    "BLOCKED by " + finding.ruleId() + " (" + Texts.clip(finding.message()) + ")" + reportSuffix, counted, allowlisted);
        }
        if (score >= BLOCK_THRESHOLD) {
            String rules = String.join(", ", counted.stream().map(Finding::ruleId).distinct().toList());
            return new Decision(Verdict.BLOCKED, score,
                    "BLOCKED: score " + score + " >= " + BLOCK_THRESHOLD + " (" + rules + "), manual review required"
                            + reportSuffix, counted, allowlisted);
        }
        String reason = counted.isEmpty()
                ? "No suspicious behavior found by the static pass (rule set " + ruleSetVersion + ")"
                : "Static pass score " + score + " < " + BLOCK_THRESHOLD + " (rule set " + ruleSetVersion + ")";
        return new Decision(Verdict.ALLOWED, score, reason + reportSuffix, counted, allowlisted);
    }

    private static int score(List<Finding> counted) {
        Map<String, Integer> weightByRule = new HashMap<>();
        for (Finding finding : counted) {
            int weight = switch (finding.severity()) {
                case CRITICAL -> BLOCK_THRESHOLD;
                case HIGH -> HIGH_WEIGHT;
                case MEDIUM -> MEDIUM_WEIGHT;
                case LOW -> 0;
            };
            weightByRule.merge(finding.ruleId(), weight, Math::max);
        }
        return weightByRule.values().stream().mapToInt(Integer::intValue).sum();
    }
}
