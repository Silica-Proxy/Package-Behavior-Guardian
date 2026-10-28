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
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tools.jackson.databind.json.JsonMapper;

class MalcontentScannerTest {

    @Test
    @SuppressWarnings("unchecked")
    void thirdPartyRulesAreAlwaysSwitchedOffExplicitly() throws IOException {
        ProcessRunner runner = mock(ProcessRunner.class);
        when(runner.runForJsonReport(anyList(), any(Duration.class), any(Path.class)))
                .thenReturn(JsonMapper.builder().build().readTree("{\"Files\": {}}"));
        MalcontentScanner scanner = new MalcontentScanner(runner, TestProperties.defaults());

        scanner.scan(new ScanContext("npm", "foo", "1.0.0", List.of(Path.of("/tmp/foo.tgz")), Path.of("/tmp")));

        ArgumentCaptor<List<String>> command = ArgumentCaptor.forClass(List.class);
        verify(runner).runForJsonReport(command.capture(), any(Duration.class), any(Path.class));
        assertThat(command.getValue()).containsExactly("mal", "--format=json", "--third-party=false", "analyze", "/tmp/foo.tgz");
    }
}
