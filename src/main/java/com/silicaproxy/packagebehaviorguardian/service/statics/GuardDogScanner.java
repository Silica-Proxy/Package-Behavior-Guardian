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
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.ToolProperties;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

/** GuardDog (Datadog, Apache-2.0) on each npm/PyPI artifact: {@code guarddog <ecosystem> scan <file> --output-format json}. */
@Component
@NullMarked
public class GuardDogScanner implements StaticScanner {

    private final ProcessRunner processRunner;
    private final ToolProperties properties;

    public GuardDogScanner(ProcessRunner processRunner, PackageBehaviorGuardianProperties properties) {
        this.processRunner = processRunner;
        this.properties = properties.scanners().guarddog();
    }

    @Override
    public String name() {
        return GuardDogReportParser.SCANNER;
    }

    @Override
    public boolean enabled() {
        return properties.enabled();
    }

    @Override
    public boolean supports(String ecosystem) {
        return "npm".equals(ecosystem) || "pypi".equals(ecosystem);
    }

    @Override
    public List<Finding> scan(ScanContext context) throws IOException {
        List<Finding> findings = new ArrayList<>();
        for (Path artifact : context.artifacts()) {
            List<String> command = new ArrayList<>(properties.command());
            command.addAll(List.of(context.ecosystem(), "scan", artifact.toString(), "--output-format", "json"));
            findings.addAll(GuardDogReportParser.parse(
                    processRunner.runForJsonReport(command, Duration.ofSeconds(properties.timeoutSeconds()), context.workDir()),
                    String.valueOf(artifact.getFileName())));
        }
        return findings;
    }
}
