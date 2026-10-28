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

import static org.assertj.core.api.Assertions.assertThat;

import com.silicaproxy.packagebehaviorguardian.TestProperties;
import com.silicaproxy.packagebehaviorguardian.model.dto.Verdict;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.AllowlistEntry;
import com.silicaproxy.packagebehaviorguardian.service.report.ReportLinks;
import java.util.List;
import org.junit.jupiter.api.Test;

class VerdictPolicyTest {

    private final VerdictPolicy policy = policy(TestProperties.defaults());

    private static VerdictPolicy policy(PackageBehaviorGuardianProperties properties) {
        return new VerdictPolicy(properties, new ReportLinks(properties));
    }

    private static Finding finding(String ruleId, Severity severity, String message) {
        return new Finding(ruleId, severity, "test", message, "loc");
    }

    @Test
    void noFindingIsAllowedWithAReportLink() {
        Decision decision = policy.decide("npm", "@scope/pkg", "1.0.0", List.of());

        assertThat(decision.verdict()).isEqualTo(Verdict.ALLOWED);
        assertThat(decision.reason()).isEqualTo("No suspicious behavior found by the static pass (rule set 1)"
                + " — report: https://pbg.internal/v1/reports?ecosystem=npm&name=%40scope%2Fpkg&version=1.0.0");
    }

    @Test
    void oneCriticalFindingBlocks() {
        Decision decision = policy.decide("npm", "foo", "1.0.0", List.of(finding("BEH-071", Severity.CRITICAL, "steals tokens")));

        assertThat(decision.verdict()).isEqualTo(Verdict.BLOCKED);
        assertThat(decision.reason()).startsWith("BLOCKED by BEH-071 (steals tokens) — report: ");
    }

    @Test
    void highAndMediumFindingsAddUpToTheThreshold() {
        Decision below = policy.decide("npm", "foo", "1.0.0", List.of(finding("JVM-004", Severity.HIGH, "m")));
        Decision atThreshold = policy.decide("npm", "foo", "1.0.0",
                List.of(finding("JVM-004", Severity.HIGH, "m"), finding("JVM-005", Severity.MEDIUM, "m"),
                        finding("JVM-006", Severity.MEDIUM, "m")));

        assertThat(below.verdict()).isEqualTo(Verdict.ALLOWED);
        assertThat(below.score()).isEqualTo(40);
        assertThat(atThreshold.verdict()).isEqualTo(Verdict.BLOCKED);
        assertThat(atThreshold.reason()).startsWith("BLOCKED: score 70 >= 60 (JVM-004, JVM-005, JVM-006), manual review required");
    }

    @Test
    void aRuleCountsOnceWhateverTheNumberOfFindings() {
        Decision decision = policy.decide("maven", "org.codehaus.mojo:exec-maven-plugin", "3.5.0", List.of(
                finding("JVM-001", Severity.MEDIUM, "a"), finding("JVM-001", Severity.MEDIUM, "b"),
                finding("JVM-001", Severity.MEDIUM, "c"), finding("JVM-001", Severity.MEDIUM, "d")));

        assertThat(decision.verdict()).isEqualTo(Verdict.ALLOWED);
        assertThat(decision.score()).isEqualTo(15);
    }

    @Test
    void allowlistedFindingsDoNotCountAndOnlyForTheirPackage() {
        VerdictPolicy withAllowlist = policy(TestProperties.withAllowlist(List.of(
                new AllowlistEntry("npm", "esbuild", null, "BEH-071", "registry.npmjs.org", "downloads its binary"))));
        Finding expected = finding("BEH-071", Severity.CRITICAL, "downloads from registry.npmjs.org");
        Finding other = finding("BEH-071", Severity.CRITICAL, "downloads from evil.example");

        Decision allowed = withAllowlist.decide("npm", "esbuild", "0.25.0", List.of(expected));
        Decision blocked = withAllowlist.decide("npm", "esbuild", "0.25.0", List.of(expected, other));
        Decision otherPackage = withAllowlist.decide("npm", "esbuild-fork", "0.25.0", List.of(expected));

        assertThat(allowed.verdict()).isEqualTo(Verdict.ALLOWED);
        assertThat(allowed.allowlisted()).containsExactly(expected);
        assertThat(blocked.verdict()).isEqualTo(Verdict.BLOCKED);
        assertThat(blocked.counted()).containsExactly(other);
        assertThat(otherPackage.verdict()).isEqualTo(Verdict.BLOCKED);
    }

    @Test
    void anEntryPinnedToAVersionDoesNotCoverTheNextRelease() {
        VerdictPolicy pinned = policy(TestProperties.withAllowlist(List.of(
                new AllowlistEntry("npm", "esbuild", "0.25.0", null, null, "reviewed 0.25.0 only"))));
        List<Finding> findings = List.of(finding("GDG-RISK", Severity.CRITICAL, "m"));

        assertThat(pinned.decide("npm", "esbuild", "0.25.0", findings).verdict()).isEqualTo(Verdict.ALLOWED);
        assertThat(pinned.decide("npm", "esbuild", "0.25.1", findings).verdict()).isEqualTo(Verdict.BLOCKED);
    }

    @Test
    void aBlankDetailIsRefusedSinceItWouldMatchEverything() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new AllowlistEntry("npm", "esbuild", null, null, " ", "typo"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
