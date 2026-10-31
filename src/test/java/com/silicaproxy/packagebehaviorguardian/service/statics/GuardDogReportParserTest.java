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


package com.silicaproxy.packagebehaviorguardian.service.statics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.groups.Tuple.tuple;

import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/** Fixtures follow the dict built by guarddog/analyzer/analyzer.py#analyze in GuardDog 3.2.0, checked against real runs. */
class GuardDogReportParserTest {

    private final ObjectMapper mapper = JsonMapper.builder().build();

    private static final String HIGH_RISK = """
            {"issues": 3, "errors": {},
             "results": {"threat_runtime_obfuscation_base64exec": [{"location": "package/index.js:3", "message": "m"}]},
             "risk_score": {"score": 7.8, "label": "high_risk", "score_breakdown": {}},
             "risks": [
               {"name": "r1", "category": "runtime", "severity": "high",
                "threat_rule": "threat_runtime_obfuscation_base64exec",
                "threat_description": "Detects base64 decoding followed by code execution",
                "threat_location": "package/index.js:3", "capability_rule": null, "file_path": "package/index.js"},
               {"name": "r2", "category": "process", "severity": "high",
                "threat_rule": "threat-process-download-exec",
                "threat_description": "Downloads then executes a binary", "threat_location": "package/install.js:9"}]}
            """;

    @Test
    void theGuardDogPackageRatingDrivesTheVerdictAndEachRiskIsReported() throws IOException {
        List<Finding> findings = GuardDogReportParser.parse(mapper.readTree(HIGH_RISK), "foo-1.0.0.tgz");

        assertThat(findings).extracting(Finding::ruleId, Finding::severity).containsExactly(
                tuple("GDG-RISK", Severity.CRITICAL),
                tuple("GDG-threat-runtime-obfuscation-base64exec", Severity.HIGH),
                tuple("GDG-threat-process-download-exec", Severity.HIGH));
        assertThat(findings.get(0).message()).isEqualTo("GuardDog rates the package high_risk (7.8/10): "
                + "Detects base64 decoding followed by code execution; Downloads then executes a binary");
        assertThat(findings.get(1).location()).isEqualTo("foo-1.0.0.tgz: package/index.js:3");
    }

    @Test
    void aSuspiciousPackageIsHighAndItsRisksAtLeastMedium() throws IOException {
        String suspicious = "{\"risk_score\": {\"score\": 5.5, \"label\": \"suspicious\"}, \"risks\": "
                + "[{\"threat_rule\": \"threat_network_outbound_shady_links\", \"severity\": \"low\", \"threat_description\": \"d\"}]}";
        String low = "{\"risk_score\": {\"score\": 2.0, \"label\": \"low\"}, \"risks\": "
                + "[{\"threat_rule\": \"threat_network_outbound_shady_links\", \"severity\": \"low\", \"threat_description\": \"d\"}]}";

        assertThat(GuardDogReportParser.parse(mapper.readTree(suspicious), "x.tgz"))
                .extracting(Finding::ruleId, Finding::severity).containsExactly(
                        tuple("GDG-RISK", Severity.HIGH), tuple("GDG-threat-network-outbound-shady-links", Severity.MEDIUM));
        assertThat(GuardDogReportParser.parse(mapper.readTree(low), "x.tgz"))
                .extracting(Finding::severity).containsExactly(Severity.LOW);
    }

    @Test
    void eachRiskCountsAtItsGuardDogSeverity() throws IOException {
        String report = """
                {"risk_score": {"score": 2.5, "label": "low"}, "risks": [
                  {"threat_rule": "threat_a", "severity": "critical", "threat_description": "a"},
                  {"threat_rule": "threat_b", "severity": "HIGH", "threat_description": "b"},
                  {"threat_rule": "threat_c", "severity": "medium", "threat_description": "c"},
                  {"threat_rule": "threat_d", "severity": "low", "threat_description": "d"},
                  {"threat_rule": "threat_e", "threat_description": "e"}]}
                """;

        assertThat(GuardDogReportParser.parse(mapper.readTree(report), "x.tgz"))
                .extracting(Finding::ruleId, Finding::severity).containsExactly(
                        tuple("GDG-threat-a", Severity.HIGH), tuple("GDG-threat-b", Severity.HIGH),
                        tuple("GDG-threat-c", Severity.MEDIUM), tuple("GDG-threat-d", Severity.LOW),
                        tuple("GDG-threat-e", Severity.LOW));
    }

    @Test
    void aCleanReportGivesNoFinding() throws IOException {
        String clean = "{\"issues\": 0, \"results\": {}, \"risk_score\": {\"score\": 0.0, \"label\": \"no_risks_detected\"}, \"risks\": []}";

        assertThat(GuardDogReportParser.parse(mapper.readTree(clean), "x.tgz")).isEmpty();
    }

    @Test
    void controlCharactersFromThePackageAreNeutralised() throws IOException {
        String report = "{\"risk_score\": {\"label\": \"low\"}, \"risks\": [{\"threat_rule\": \"threat_x\", \"threat_description\": \"d\","
                + " \"threat_location\": \"a.js\\n[FAKE LOG]\"}]}";

        assertThat(GuardDogReportParser.parse(mapper.readTree(report), "x.tgz").get(0).location()).doesNotContain("\n");
    }

    @Test
    void anIncompleteScanIsAFailureNotACleanResult() {
        assertThatThrownBy(() -> GuardDogReportParser.parse(mapper.readTree("{\"issues\": 0}"), "x.tgz"))
                .isInstanceOf(IOException.class).hasMessageContaining("risk_score");
        String withErrors = "{\"errors\": {\"threat-x\": \"failed to run rule\"}, \"risk_score\": {\"label\": \"no_risks_detected\"}}";
        assertThatThrownBy(() -> GuardDogReportParser.parse(mapper.readTree(withErrors), "x.tgz"))
                .isInstanceOf(IOException.class).hasMessageContaining("rule errors");
    }
}
