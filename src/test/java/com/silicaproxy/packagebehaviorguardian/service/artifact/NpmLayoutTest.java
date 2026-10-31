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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import org.junit.jupiter.api.Test;

class NpmLayoutTest {

    @Test
    void theTarballOfTheVersionIsAccepted() {
        URI tarball = URI.create("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz");

        assertThat(NpmLayout.requireTarball(tarball, "lodash", "4.17.21")).isEqualTo(tarball);
        assertThat(NpmLayout.requireTarball(URI.create("https://silica.internal:8443/npm/lodash/-/lodash-4.17.21.tgz"),
                "lodash", "4.17.21")).isNotNull();
    }

    @Test
    void aScopedTarballIsNamedAfterTheBasename() {
        assertThat(NpmLayout.requireTarball(URI.create("https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz"),
                "@babel/core", "7.24.0")).isNotNull();
        assertThat(NpmLayout.requireTarball(URI.create("https://registry.npmjs.org/@babel%2fcore/-/core-7.24.0.tgz"),
                "@babel/core", "7.24.0")).isNotNull();
        assertThat(NpmLayout.requireTarball(URI.create("https://registry.npmjs.org/@babel%2Fcore/-/core-7.24.0.tgz"),
                "@babel/core", "7.24.0")).isNotNull();
    }

    @Test
    void anotherPackageOrVersionIsRefused() {
        assertThatThrownBy(() -> NpmLayout.requireTarball(URI.create("https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"),
                "lodash", "4.17.21")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> NpmLayout.requireTarball(URI.create("https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"),
                "lodash", "4.17.21")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> NpmLayout.requireTarball(URI.create("https://registry.npmjs.org/left-pad/-/pad-1.0.0.tgz"),
                "pad", "1.0.0")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anotherScopeIsRefused() {
        assertThatThrownBy(() -> NpmLayout.requireTarball(URI.create("https://registry.npmjs.org/@evil/core/-/core-7.24.0.tgz"),
                "@babel/core", "7.24.0")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> NpmLayout.requireTarball(URI.create("https://registry.npmjs.org/core/-/core-7.24.0.tgz"),
                "@babel/core", "7.24.0")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aFileThatIsNotTheTarballIsRefused() {
        assertThatThrownBy(() -> NpmLayout.requireTarball(URI.create("https://registry.npmjs.org/lodash"),
                "lodash", "4.17.21")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> NpmLayout.requireTarball(URI.create("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz/x"),
                "lodash", "4.17.21")).isInstanceOf(IllegalArgumentException.class);
    }
}
