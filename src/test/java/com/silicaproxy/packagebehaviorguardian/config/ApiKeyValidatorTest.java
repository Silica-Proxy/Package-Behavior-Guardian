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

import com.silicaproxy.packagebehaviorguardian.TestProperties;
import org.junit.jupiter.api.Test;

class ApiKeyValidatorTest {

    private final ApiKeyValidator validator = new ApiKeyValidator(TestProperties.defaults());

    @Test
    void eachScopeAcceptsOnlyItsOwnKey() {
        assertThat(validator.isAuthorized(Scope.CHECK, "check-key")).isTrue();
        assertThat(validator.isAuthorized(Scope.REPORT, "report-key")).isTrue();
        assertThat(validator.isAuthorized(Scope.REPORT, "check-key")).isFalse();
        assertThat(validator.isAuthorized(Scope.CHECK, "report-key")).isFalse();
    }

    @Test
    void aMissingKeyIsRefused() {
        assertThat(validator.isAuthorized(Scope.CHECK, null)).isFalse();
    }
}
