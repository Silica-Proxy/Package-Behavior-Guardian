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


package com.silicaproxy.packagebehaviorguardian.service.artifact;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class RegistryClientTest {

    @Test
    void everyFileOfAPypiVersionIsListedYankedOnesIncluded() {
        String json = """
                {"urls": [
                  {"url": "https://files.pythonhosted.org/a/foo-1.0-py3-none-any.whl", "packagetype": "bdist_wheel"},
                  {"url": "https://files.pythonhosted.org/b/foo-1.0.tar.gz", "packagetype": "sdist"},
                  {"url": "https://files.pythonhosted.org/c/foo-1.0-cp312.whl", "packagetype": "bdist_wheel", "yanked": true},
                  {"packagetype": "sdist"}]}
                """;

        // A yanked file is still installed when the exact version is pinned (PEP 592).
        assertThat(RegistryClient.pypiVersionFiles(JsonMapper.builder().build().readTree(json))).containsExactly(
                "https://files.pythonhosted.org/a/foo-1.0-py3-none-any.whl", "https://files.pythonhosted.org/b/foo-1.0.tar.gz",
                "https://files.pythonhosted.org/c/foo-1.0-cp312.whl");
    }
}
