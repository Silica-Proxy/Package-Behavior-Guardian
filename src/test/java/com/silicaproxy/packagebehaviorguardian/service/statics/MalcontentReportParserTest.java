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
import static org.assertj.core.groups.Tuple.tuple;

import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

class MalcontentReportParserTest {

    private final ObjectMapper mapper = JsonMapper.builder().build();

    @Test
    void aCriticalFileGivesBeh071() {
        String report = """
                {"Files": {
                  "package/index.js": {"RiskLevel": "CRITICAL", "Behaviors": [
                    {"ID": "exfil/stealer/browser", "Description": "steals browser cookies", "RiskLevel": "CRITICAL"},
                    {"ID": "net/http/request", "Description": "makes HTTP requests", "RiskLevel": "MEDIUM"}]},
                  "package/util.js": {"RiskLevel": "HIGH", "Behaviors": []}
                }}
                """;

        List<Finding> findings = MalcontentReportParser.parse(mapper.readTree(report), "foo-2.0.0.tgz");

        assertThat(findings).hasSize(2);
        assertThat(findings.get(0).ruleId()).isEqualTo("BEH-071");
        assertThat(findings.get(0).severity()).isEqualTo(Severity.CRITICAL);
        assertThat(findings.get(0).message()).contains("steals browser cookies").doesNotContain("HTTP requests");
    }

    @Test
    void highAndMediumFilesGiveBeh072AndBeh073() {
        String report = """
                {"Files": {
                  "package/setup.js": {"RiskLevel": "MEDIUM", "Behaviors": [
                    {"ID": "net/http/request", "Description": "makes HTTP requests", "RiskLevel": "MEDIUM"},
                    {"ID": "fs/file/read", "Description": "reads files", "RiskLevel": "LOW"}]},
                  "package/index.js": {"RiskLevel": "HIGH", "Behaviors": [
                    {"ID": "evasion/obfuscation/hex", "Description": "hex-encoded payload", "RiskLevel": "HIGH"}]},
                  "package/readme.md": {"RiskLevel": "LOW", "Behaviors": []}
                }}
                """;

        List<Finding> findings = MalcontentReportParser.parse(mapper.readTree(report), "foo-2.0.0.tgz");

        assertThat(findings).extracting(Finding::ruleId, Finding::severity).containsExactly(
                tuple("BEH-072", Severity.HIGH), tuple("BEH-073", Severity.MEDIUM));
        assertThat(findings.get(0).message()).isEqualTo("malcontent rates this file HIGH: hex-encoded payload");
        assertThat(findings.get(1).message()).isEqualTo("malcontent rates this file MEDIUM: makes HTTP requests");
        assertThat(findings.get(1).location()).isEqualTo("foo-2.0.0.tgz: package/setup.js");
    }

    @Test
    void theFindingCapKeepsTheCriticalFilesFirst() {
        StringBuilder files = new StringBuilder();
        for (int i = 0; i < 25; i++) {
            files.append("\"package/m").append(i).append(".js\": {\"RiskLevel\": \"MEDIUM\"}, ");
        }
        String report = "{\"Files\": {" + files + "\"package/z.js\": {\"RiskLevel\": \"CRITICAL\"}}}";

        List<Finding> findings = MalcontentReportParser.parse(mapper.readTree(report), "x.tgz");

        assertThat(findings).hasSize(20);
        assertThat(findings.get(0).ruleId()).isEqualTo("BEH-071");
    }

    @Test
    void aReportWithoutFilesGivesNoFinding() {
        assertThat(MalcontentReportParser.parse(mapper.readTree("{}"), "x.tgz")).isEmpty();
    }
}
