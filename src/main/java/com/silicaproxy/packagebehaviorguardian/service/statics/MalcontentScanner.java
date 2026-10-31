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
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.MalcontentProperties;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

/**
 * malcontent (Chainguard, Apache-2.0) on every artifact of every ecosystem, binaries included:
 * {@code mal analyze}. Third-party rules are switched off explicitly unless {@code
 * third-party-rules} is set: malcontent itself enables them by default.
 */
@Component
@NullMarked
public class MalcontentScanner implements FileScanner {

    private final ProcessRunner processRunner;
    private final MalcontentProperties properties;

    public MalcontentScanner(ProcessRunner processRunner, PackageBehaviorGuardianProperties properties) {
        this.processRunner = processRunner;
        this.properties = properties.scanners().malcontent();
    }

    @Override
    public String name() {
        return MalcontentReportParser.SCANNER;
    }

    @Override
    public boolean enabled() {
        return properties.enabled();
    }

    @Override
    public boolean supports(String ecosystem) {
        return true;
    }

    // Same rules whatever the ecosystem; third-party rules change the findings.
    @Override
    public String cacheKey(String ecosystem) {
        return properties.thirdPartyRules() ? name() + ":third-party" : name();
    }

    @Override
    public List<Finding> scanFile(String ecosystem, Path artifact, Path workDir) throws IOException {
        List<String> command = new ArrayList<>(properties.command());
        command.addAll(List.of("--format=json", "--third-party=" + properties.thirdPartyRules(), "analyze", artifact.toString()));
        return MalcontentReportParser.parse(
                processRunner.runForJsonReport(command, Duration.ofSeconds(properties.timeoutSeconds()), workDir),
                String.valueOf(artifact.getFileName()));
    }
}
