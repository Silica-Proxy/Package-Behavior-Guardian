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

package com.silicaproxy.packagebehaviorguardian.properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.CallbackProperties;
import java.time.Duration;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class CallbackPropertiesTest {

    private final CallbackProperties defaults = new CallbackProperties(11, 10, 300);

    @Test
    void theDelayDoublesAfterEachFailureUpToTheCap() {
        assertThat(IntStream.rangeClosed(1, 10).mapToLong(attempts -> defaults.retryDelay(attempts).toSeconds()).toArray())
                .containsExactly(10, 20, 40, 80, 160, 300, 300, 300, 300, 300);
    }

    @Test
    void theDefaultsKeepRetryingForAboutThirtyMinutes() {
        Duration window = IntStream.range(1, defaults.maxAttempts())
                .mapToObj(defaults::retryDelay)
                .reduce(Duration.ZERO, Duration::plus);

        assertThat(window).isEqualTo(Duration.ofMinutes(30).plusSeconds(10));
    }

    @Test
    void manyAttemptsNeitherOverflowNorExceedTheCap() {
        assertThat(defaults.retryDelay(Integer.MAX_VALUE)).isEqualTo(Duration.ofSeconds(300));
        assertThat(new CallbackProperties(3, Integer.MAX_VALUE, Integer.MAX_VALUE).retryDelay(64))
                .isEqualTo(Duration.ofSeconds(Integer.MAX_VALUE));
    }

    @Test
    void inconsistentSettingsAreRefused() {
        assertThatThrownBy(() -> new CallbackProperties(0, 10, 300)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CallbackProperties(11, 0, 300)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CallbackProperties(11, 10, 5)).isInstanceOf(IllegalArgumentException.class);
    }
}
