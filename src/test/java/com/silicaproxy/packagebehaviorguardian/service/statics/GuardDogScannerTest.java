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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.silicaproxy.packagebehaviorguardian.TestProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.GuardDogProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.ScannerProperties;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tools.jackson.databind.json.JsonMapper;

class GuardDogScannerTest {

    @Test
    void theSandboxIsKeptByDefault() throws IOException {
        assertThat(commandWith(TestProperties.defaults()))
                .containsExactly("guarddog", "npm", "scan", "/work/job/0-foo.tgz", "--output-format", "json");
    }

    @Test
    void sandboxFalsePassesNoSandbox() throws IOException {
        PackageBehaviorGuardianProperties defaults = TestProperties.defaults();
        PackageBehaviorGuardianProperties properties = new PackageBehaviorGuardianProperties(defaults.security(), defaults.intake(),
                defaults.artifact(), defaults.registries(), defaults.queue(), defaults.callback(), defaults.retention(), defaults.analysis(),
                new ScannerProperties(new GuardDogProperties(true, List.of("guarddog"), 300, false), defaults.scanners().malcontent(),
                        defaults.scanners().bytecode(), defaults.scanners().isolation()),
                defaults.allowlist(), defaults.gitops(), defaults.corporateProxy());

        assertThat(commandWith(properties))
                .containsExactly("guarddog", "npm", "scan", "/work/job/0-foo.tgz", "--output-format", "json", "--no-sandbox");
    }

    @SuppressWarnings("unchecked")
    private static List<String> commandWith(PackageBehaviorGuardianProperties properties) throws IOException {
        ProcessRunner runner = mock(ProcessRunner.class);
        when(runner.runForJsonReport(anyList(), any(Duration.class), any(Path.class)))
                .thenReturn(JsonMapper.builder().build().readTree("{\"issues\": 0, \"results\": {}, \"risk_score\": {\"score\": 0.0, \"label\": \"no_risks_detected\"}, \"risks\": []}"));

        new GuardDogScanner(runner, properties).scanFile("npm", Path.of("/work/job/0-foo.tgz"), Path.of("/work/job"));

        ArgumentCaptor<List<String>> command = ArgumentCaptor.forClass(List.class);
        verify(runner).runForJsonReport(command.capture(), any(Duration.class), any(Path.class));
        return command.getValue();
    }
}
