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

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.json.JsonMapper;

@DisabledOnOs(OS.WINDOWS)
class ProcessRunnerTest {

    @TempDir
    Path workDir;

    private final ProcessRunner runner = new ProcessRunner(JsonMapper.builder().build());

    private List<String> environmentSeenByTheTool(Map<String, String> parentEnvironment) throws IOException {
        return runner.run(List.of("/usr/bin/env"), Duration.ofSeconds(10), workDir, parentEnvironment).stdout().lines().toList();
    }

    @Test
    void guardDogSettingsReachTheToolButNotTheServiceSecrets() throws IOException {
        List<String> environment = environmentSeenByTheTool(Map.of(
                "PATH", "/usr/bin:/bin",
                "GUARDDOG_TOP_PACKAGES_CACHE_LOCATION", "/var/cache/guarddog",
                "GUARDDOG_UNSET", "",
                "SPRING_DATASOURCE_PASSWORD", "secret",
                "PACKAGEBEHAVIORGUARDIAN_API_KEY", "secret"));

        assertThat(environment).contains("GUARDDOG_TOP_PACKAGES_CACHE_LOCATION=/var/cache/guarddog", "TMPDIR=" + workDir, "HOME=" + workDir)
                .noneMatch(line -> line.startsWith("GUARDDOG_UNSET=") || line.contains("secret"));
        assertThat(environment).extracting(line -> line.substring(0, line.indexOf('=')))
                .containsExactlyInAnyOrder("PATH", "HOME", "LANG", "TMPDIR", "GUARDDOG_TOP_PACKAGES_CACHE_LOCATION");
    }

    @Test
    void aToolThatRunsTooLongIsKilled() {
        assertThatThrownBy(() -> runner.run(List.of("/bin/sleep", "30"), Duration.ofMillis(300), workDir))
                .isInstanceOf(IOException.class).hasMessageContaining("timed out");
    }

    @Test
    void invalidUtf8OnStderrIsReportedNotFatal() {
        assertThatThrownBy(() -> runner.runForJsonReport(List.of("/bin/sh", "-c", "printf 'boom \\377\\376' >&2; exit 3"),
                Duration.ofSeconds(10), workDir))
                .isInstanceOf(IOException.class).hasMessageContaining("exited with 3").hasMessageContaining("boom");
    }

    @Test
    void aToolThatPrintsNoJsonFailsTheScan() {
        assertThatThrownBy(() -> runner.runForJsonReport(List.of("/bin/echo", "not json"), Duration.ofSeconds(10), workDir))
                .isInstanceOf(IOException.class).hasMessageContaining("without a JSON report");
    }
}
