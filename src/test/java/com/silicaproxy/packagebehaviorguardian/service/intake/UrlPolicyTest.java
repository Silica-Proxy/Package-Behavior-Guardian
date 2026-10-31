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


package com.silicaproxy.packagebehaviorguardian.service.intake;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.silicaproxy.packagebehaviorguardian.TestProperties;
import org.junit.jupiter.api.Test;

class UrlPolicyTest {

    private final UrlPolicy policy = new UrlPolicy(TestProperties.defaults());

    @Test
    void anAllowedHttpsHostIsAccepted() {
        assertThat(policy.requireArtifactUrl("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz").getHost())
                .isEqualTo("registry.npmjs.org");
    }

    @Test
    void hostsAreMatchedExactlyNotBySuffix() {
        assertThatThrownBy(() -> policy.requireArtifactUrl("https://evil-registry.npmjs.org.attacker.com/x.tgz"))
                .isInstanceOf(UrlRejectedException.class);
        assertThatThrownBy(() -> policy.requireArtifactUrl("https://npmjs.org/x.tgz"))
                .isInstanceOf(UrlRejectedException.class);
    }

    @Test
    void plainHttpIsAccepted() {
        assertThat(policy.requireArtifactUrl("http://registry.npmjs.org/x.tgz")).isNotNull();
        assertThatThrownBy(() -> policy.requireArtifactUrl("ftp://registry.npmjs.org/x.tgz"))
                .isInstanceOf(UrlRejectedException.class);
    }

    @Test
    void anEntryNamingTheDefaultPortMeansTheBareHost() {
        UrlPolicy explicitPort = new UrlPolicy(new com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties(
                null, new com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.IntakeProperties(
                        java.util.List.of("registry.npmjs.org:443"), java.util.List.of("silicaproxy:80")),
                null, null, null, null, null, null, null, java.util.List.of()));

        assertThat(explicitPort.requireArtifactUrl("https://registry.npmjs.org/x.tgz")).isNotNull();
        assertThat(explicitPort.requireCallbackUrl("http://silicaproxy/external-validation/callback/x")).isNotNull();
    }

    @Test
    void userInfoIsRefused() {
        assertThatThrownBy(() -> policy.requireArtifactUrl("https://user@registry.npmjs.org/x.tgz"))
                .isInstanceOf(UrlRejectedException.class);
    }

    @Test
    void aNonDefaultPortMustBeListed() {
        assertThat(policy.requireArtifactUrl("https://silica.internal:8443/npm/x.tgz")).isNotNull();
        assertThatThrownBy(() -> policy.requireArtifactUrl("https://registry.npmjs.org:8443/x.tgz"))
                .isInstanceOf(UrlRejectedException.class);
        assertThat(policy.requireArtifactUrl("https://registry.npmjs.org:443/x.tgz")).isNotNull();
    }

    @Test
    void aWildcardPortEntryAcceptsAnyPortOfThatHostOnly() {
        assertThat(policy.requireArtifactUrl("https://localhost:12345/x.tgz")).isNotNull();
        assertThatThrownBy(() -> policy.requireArtifactUrl("https://127.0.0.1:12345/x.tgz"))
                .isInstanceOf(UrlRejectedException.class);
    }

    @Test
    void callbackAndArtifactHostListsAreSeparate() {
        assertThat(policy.requireCallbackUrl("https://silica.internal/external-validation/callback/abc")).isNotNull();
        assertThatThrownBy(() -> policy.requireCallbackUrl("https://registry.npmjs.org/callback"))
                .isInstanceOf(UrlRejectedException.class);
    }

    @Test
    void relativeAndMalformedUrlsAreRefused() {
        assertThatThrownBy(() -> policy.requireArtifactUrl("/lodash.tgz")).isInstanceOf(UrlRejectedException.class);
        assertThatThrownBy(() -> policy.requireArtifactUrl("https://registry.npmjs.org/a b")).isInstanceOf(UrlRejectedException.class);
    }
}
