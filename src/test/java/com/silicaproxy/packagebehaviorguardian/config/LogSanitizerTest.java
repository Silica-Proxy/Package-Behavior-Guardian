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

package com.silicaproxy.packagebehaviorguardian.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void replacesControlCharactersWithUnderscore() {
        assertThat(LogSanitizer.sanitize("a\r\nb\tc\u0000d")).isEqualTo("a__b_c_d");
    }

    @Test
    void leavesPlainValuesUntouched() {
        assertThat(LogSanitizer.sanitize("@scope/pkg-1.0")).isEqualTo("@scope/pkg-1.0");
    }

    @Test
    void passesNullThrough() {
        assertThat(LogSanitizer.sanitize(null)).isNull();
    }
}
