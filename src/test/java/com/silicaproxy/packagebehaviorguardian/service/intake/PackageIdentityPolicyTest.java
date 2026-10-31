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

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import org.junit.jupiter.api.Test;

class PackageIdentityPolicyTest {

    private static final URI PYPI_FILE = URI.create("https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0.tar.gz");

    private static void accepted(String ecosystem, String name, String version, String url) {
        assertThatCode(() -> PackageIdentityPolicy.require(ecosystem, name, version, URI.create(url))).doesNotThrowAnyException();
    }

    private static void refused(String ecosystem, String name, String version, String url) {
        assertThatThrownBy(() -> PackageIdentityPolicy.require(ecosystem, name, version, URI.create(url)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validNpmNamesAreAccepted() {
        accepted("npm", "left-pad", "1.3.0", "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz");
        accepted("npm", "@types/node", "20.11.5", "https://registry.npmjs.org/@types/node/-/node-20.11.5.tgz");
        accepted("npm", "JSONStream", "1.3.5", "https://registry.npmjs.org/JSONStream/-/JSONStream-1.3.5.tgz");
        accepted("npm", "lodash.merge", "4.6.2", "https://registry.npmjs.org/lodash.merge/-/lodash.merge-4.6.2.tgz");
    }

    @Test
    void npmNamesOutsideTheRegistryCharsetAreRefused() {
        refused("npm", "..", "1.0.0", "https://registry.npmjs.org/../-/..-1.0.0.tgz");
        refused("npm", "a/../b", "1.0.0", "https://registry.npmjs.org/a/../b/-/b-1.0.0.tgz");
        refused("npm", "@scope/..", "1.0.0", "https://registry.npmjs.org/@scope/../-/..-1.0.0.tgz");
        refused("npm", "a..b", "1.0.0", "https://registry.npmjs.org/a..b/-/a..b-1.0.0.tgz");
        refused("npm", ".hidden", "1.0.0", "https://registry.npmjs.org/.hidden/-/.hidden-1.0.0.tgz");
        refused("npm", "a:b", "1.0.0", "https://registry.npmjs.org/a:b/-/a:b-1.0.0.tgz");
        refused("npm", "scope/name", "1.0.0", "https://registry.npmjs.org/scope/name/-/name-1.0.0.tgz");
    }

    @Test
    void anNpmUrlMustBeTheTarballOfTheRequestedVersion() {
        refused("npm", "left-pad", "1.3.0", "https://registry.npmjs.org/evil-pkg/-/evil-pkg-2.0.0.tgz");
        refused("npm", "left-pad", "1.3.0", "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz");
        refused("npm", "@types/node", "20.11.5", "https://registry.npmjs.org/@evil/node/-/node-20.11.5.tgz");
    }

    @Test
    void pypiNamesFollowPep508() {
        assertThatCode(() -> PackageIdentityPolicy.require("pypi", "zope.interface", "6.1", PYPI_FILE)).doesNotThrowAnyException();
        assertThatCode(() -> PackageIdentityPolicy.require("pypi", "Django_REST-framework", "3.14.0", PYPI_FILE))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> PackageIdentityPolicy.require("pypi", "../etc", "1.0", PYPI_FILE))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PackageIdentityPolicy.require("pypi", "a/b", "1.0", PYPI_FILE))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PackageIdentityPolicy.require("pypi", "-dash", "1.0", PYPI_FILE))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void mavenCoordinatesMustBeBoundToTheUrl() {
        accepted("maven", "org.example:my-lib", "1.0", "https://repo1.maven.org/maven2/org/example/my-lib/1.0/my-lib-1.0.pom");
        refused("maven", "org.example:my-lib", "1.0", "https://repo1.maven.org/maven2/org/evil/my-lib/1.0/my-lib-1.0.pom");
        refused("maven", "org.example:my-lib", "1.0", "https://repo1.maven.org/maven2/org/example/my-lib/2.0/my-lib-2.0.jar");
    }

    @Test
    void mavenCoordinatesOutsideTheSafeCharsetAreRefused() {
        refused("maven", "org..example:lib", "1.0", "https://repo1.maven.org/maven2/org//example/lib/1.0/lib-1.0.pom");
        refused("maven", ".org:lib", "1.0", "https://repo1.maven.org/maven2//org/lib/1.0/lib-1.0.pom");
        refused("maven", "org/evil:lib", "1.0", "https://repo1.maven.org/maven2/org/evil/lib/1.0/lib-1.0.pom");
        refused("maven", "org.example:..", "1.0", "https://repo1.maven.org/maven2/org/example/../1.0/..-1.0.pom");
        refused("maven", "org.example:a/b", "1.0", "https://repo1.maven.org/maven2/org/example/a/b/1.0/a/b-1.0.pom");
    }

    @Test
    void versionsMustNotTraversePaths() {
        String url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
        refused("npm", "left-pad", ".", url);
        refused("npm", "left-pad", "..", url);
        refused("npm", "left-pad", "1.0/../../x", url);
        refused("npm", "left-pad", "1.0\\..", url);
        refused("maven", "org.example:my-lib", "..", "https://repo1.maven.org/maven2/org/example/my-lib/../my-lib-...pom");
        refused("maven", "org.example:my-lib", "1.0%2f..", "https://repo1.maven.org/maven2/org/example/my-lib/1.0%2f../my-lib-1.0%2f...pom");
        refused("pypi", "requests", "../2.0", PYPI_FILE.toString());
    }
}
