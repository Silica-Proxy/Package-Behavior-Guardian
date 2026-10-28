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
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.jspecify.annotations.NullMarked;
import tools.jackson.databind.JsonNode;

/**
 * Turns a GuardDog 3.x {@code --output-format json} report into findings. GuardDog 3 correlates its
 * YARA threat and capability rules into {@code risks} and rates the package with {@code
 * risk_score.label} (no_risks_detected / low / suspicious / high_risk). That calibrated rating drives
 * the verdict: {@code high_risk} gives a CRITICAL {@code GDG-RISK}, {@code suspicious} a HIGH one.
 * Each risk is also kept, as a LOW {@code GDG-<threat rule>} that does not count, so the report shows
 * why. Rule names are normalized to dashes (YARA reports them with underscores).
 */
@NullMarked
public final class GuardDogReportParser {

    public static final String SCANNER = "guarddog";
    public static final String PACKAGE_RISK_RULE = "GDG-RISK";
    private static final int MAX_RISKS = 30;

    private GuardDogReportParser() {
    }

    /** Throws when GuardDog did not rate the package or reports rule errors: an incomplete scan is not a clean one. */
    public static List<Finding> parse(JsonNode report, String artifactName) throws IOException {
        if (!report.path("risk_score").isObject()) {
            throw new IOException("GuardDog report without risk_score for " + artifactName);
        }
        if (!report.path("errors").isEmpty()) {
            throw new IOException("GuardDog rule errors for " + artifactName + ": " + Texts.clip(report.path("errors").toString()));
        }
        List<Finding> findings = new ArrayList<>();
        List<String> threats = new ArrayList<>();
        for (JsonNode risk : report.path("risks")) {
            String rule = risk.path("threat_rule").asString("").replace('_', '-').toLowerCase(Locale.ROOT);
            if (rule.isEmpty() || findings.size() >= MAX_RISKS) {
                continue;
            }
            String description = risk.path("threat_description").asString(rule);
            String location = risk.path("threat_location").asString(risk.path("file_path").asString(""));
            threats.add(description);
            findings.add(new Finding("GDG-" + Texts.clip(rule), Severity.LOW, SCANNER,
                    Texts.clip(description + " (GuardDog severity " + risk.path("severity").asString("?") + ")"),
                    Texts.clip(location.isEmpty() ? artifactName : artifactName + ": " + location)));
        }
        JsonNode score = report.path("risk_score");
        Severity packageSeverity = switch (score.path("label").asString("")) {
            case "high_risk" -> Severity.CRITICAL;
            case "suspicious" -> Severity.HIGH;
            default -> null;
        };
        if (packageSeverity != null) {
            findings.add(0, new Finding(PACKAGE_RISK_RULE, packageSeverity, SCANNER,
                    Texts.clip("GuardDog rates the package " + score.path("label").asString() + " (" + score.path("score").asDouble(0)
                            + "/10): " + String.join("; ", threats.stream().distinct().toList())),
                    Texts.clip(artifactName)));
        }
        return findings;
    }
}
