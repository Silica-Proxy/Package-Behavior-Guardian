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

import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.NullMarked;
import tools.jackson.databind.JsonNode;

/**
 * Turns {@code mal --format=json analyze} output into findings: {@code Files} maps each file to a
 * report with a {@code RiskLevel} and its {@code Behaviors}; every file rated CRITICAL gives BEH-071.
 */
@NullMarked
public final class MalcontentReportParser {

    public static final String SCANNER = "malcontent";
    public static final String CRITICAL_RISK_RULE = "BEH-071";
    private static final int MAX_FINDINGS = 20;

    private MalcontentReportParser() {
    }

    public static List<Finding> parse(JsonNode report, String artifactName) {
        List<Finding> findings = new ArrayList<>();
        for (Map.Entry<String, JsonNode> file : report.path("Files").properties()) {
            if (!isCritical(file.getValue()) || findings.size() >= MAX_FINDINGS) {
                continue;
            }
            List<String> critical = new ArrayList<>();
            for (JsonNode behavior : file.getValue().path("Behaviors")) {
                if (isCritical(behavior)) {
                    critical.add(behavior.path("Description").asString(behavior.path("ID").asString("?")));
                }
            }
            findings.add(new Finding(CRITICAL_RISK_RULE, Severity.CRITICAL, SCANNER,
                    Texts.clip("malcontent rates this file CRITICAL: " + String.join("; ", critical)),
                    Texts.clip(artifactName + ": " + file.getKey())));
        }
        return findings;
    }

    private static boolean isCritical(JsonNode node) {
        return "CRITICAL".equalsIgnoreCase(node.path("RiskLevel").asString(""));
    }
}
