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
import com.silicaproxy.packagebehaviorguardian.service.statics.GuardDogReportParser;
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
 * CRITICAL blocks; otherwise HIGH and MEDIUM findings add up (weights {@code analysis.high-weight},
 * {@code medium-weight}, default 40 and 20) -- each rule once, at its
 * highest severity, so that one behavior repeated in ten methods does not outweigh two distinct
 * behaviors -- and a score of {@code analysis.block-threshold} (default 60) or more blocks with
 * "manual review required". So a HIGH signal corroborated by another rule (HIGH + MEDIUM, a GuardDog
 * {@code suspicious} rating and one of its risks, two HIGH) or three distinct MEDIUM rules block,
 * while a lone HIGH, one or two MEDIUM and LOW findings (report only) do not. Two verdicts only:
 * the grey zone is a BLOCKED with the report link, released through a SilicaProxy GitOps policy or
 * an allowlist entry here. The reason quotes the rule ID and the description of the first
 * CRITICAL finding -- this service's or the scanner's rule description, clipped and stripped of
 * control characters (a location, which may come from the package, is never quoted).
 */
@Component
@NullMarked
public class VerdictPolicy {

    private static final String GUARDDOG_RULE_PREFIX = "GDG-";

    private final List<AllowlistEntry> allowlist;
    private final String ruleSetVersion;
    private final ReportLinks reportLinks;
    private final int highWeight;
    private final int mediumWeight;
    private final int blockThreshold;

    public VerdictPolicy(PackageBehaviorGuardianProperties properties, ReportLinks reportLinks) {
        this.allowlist = List.copyOf(properties.allowlist());
        this.ruleSetVersion = properties.analysis().ruleSetVersion();
        this.reportLinks = reportLinks;
        this.highWeight = properties.analysis().highWeight();
        this.mediumWeight = properties.analysis().mediumWeight();
        this.blockThreshold = properties.analysis().blockThreshold();
    }

    public Decision decide(String ecosystem, String name, String version, List<Finding> findings) {
        List<Finding> counted = new ArrayList<>();
        List<Finding> allowlisted = new ArrayList<>();
        for (Finding finding : findings) {
            (allowlist.stream().anyMatch(entry -> entry.covers(ecosystem, name, version, finding)) ? allowlisted : counted).add(finding);
        }
        // GuardDog's rating is made of its risks: once one of them is not allowlisted (a threat that
        // appeared after the entry was written), the rating counts again, whatever the entry's detail matched.
        if (counted.stream().anyMatch(VerdictPolicy::isGuardDogRisk)) {
            List<Finding> ratings = allowlisted.stream().filter(VerdictPolicy::isGuardDogRating).toList();
            allowlisted.removeAll(ratings);
            counted.addAll(ratings);
        }
        String reportSuffix = reportLinks.suffix(ecosystem, name, version);

        Optional<Finding> critical = counted.stream().filter(finding -> finding.severity() == Severity.CRITICAL).findFirst();
        int score = score(counted);
        if (critical.isPresent()) {
            Finding finding = critical.get();
            return new Decision(Verdict.BLOCKED, score,
                    "BLOCKED by " + finding.ruleId() + " (" + Texts.clip(finding.message()) + ")" + reportSuffix, counted, allowlisted);
        }
        if (score >= blockThreshold) {
            String rules = String.join(", ", counted.stream().map(Finding::ruleId).distinct().toList());
            return new Decision(Verdict.BLOCKED, score,
                    "BLOCKED: score " + score + " >= " + blockThreshold + " (" + rules + "), manual review required"
                            + reportSuffix, counted, allowlisted);
        }
        String reason = counted.isEmpty()
                ? "No suspicious behavior found by the static pass (rule set " + ruleSetVersion + ")"
                : "Static pass score " + score + " < " + blockThreshold + " (rule set " + ruleSetVersion + ")";
        return new Decision(Verdict.ALLOWED, score, reason + reportSuffix, counted, allowlisted);
    }

    private static boolean isGuardDogRating(Finding finding) {
        return GuardDogReportParser.PACKAGE_RISK_RULE.equals(finding.ruleId());
    }

    private static boolean isGuardDogRisk(Finding finding) {
        return finding.ruleId().startsWith(GUARDDOG_RULE_PREFIX) && !isGuardDogRating(finding);
    }

    private int score(List<Finding> counted) {
        Map<String, Integer> weightByRule = new HashMap<>();
        for (Finding finding : counted) {
            int weight = switch (finding.severity()) {
                case CRITICAL -> blockThreshold;
                case HIGH -> highWeight;
                case MEDIUM -> mediumWeight;
                case LOW -> 0;
            };
            weightByRule.merge(finding.ruleId(), weight, Math::max);
        }
        return weightByRule.values().stream().mapToInt(Integer::intValue).sum();
    }
}
