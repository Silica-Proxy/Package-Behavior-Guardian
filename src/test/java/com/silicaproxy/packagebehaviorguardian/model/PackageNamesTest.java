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


package com.silicaproxy.packagebehaviorguardian.model;

import static org.assertj.core.api.Assertions.assertThat;

import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.AllowlistEntry;
import org.junit.jupiter.api.Test;

class PackageNamesTest {

    private static final Finding FINDING = new Finding("BEH-001", Severity.HIGH, "malcontent", "m", null);

    @Test
    void pypiNamesFollowPep503() {
        assertThat(PackageNames.normalize("pypi", "Foo_Bar")).isEqualTo("foo-bar");
        assertThat(PackageNames.normalize("pypi", "foo-bar")).isEqualTo("foo-bar");
        assertThat(PackageNames.normalize("pypi", "FOO.bar")).isEqualTo("foo-bar");
        assertThat(PackageNames.normalize("pypi", "foo__-.bar")).isEqualTo("foo-bar");
        assertThat(PackageNames.normalize("pypi", "zope.interface")).isEqualTo("zope-interface");
        assertThat(PackageNames.normalize("pypi", "Django")).isEqualTo("django");
    }

    @Test
    void npmAndMavenNamesAreCaseSensitiveAndKeptAsWritten() {
        // Legacy mixed-case npm packages live under their exact spelling; "jsonstream" is another name.
        assertThat(PackageNames.normalize("npm", "JSONStream")).isEqualTo("JSONStream");
        assertThat(PackageNames.normalize("npm", "@Scope/Foo_Bar")).isEqualTo("@Scope/Foo_Bar");
        assertThat(PackageNames.normalize("maven", "com.Example:My_Lib")).isEqualTo("com.Example:My_Lib");
    }

    @Test
    void allowlistEntriesMatchEverySpellingOfAPypiName() {
        AllowlistEntry entry = new AllowlistEntry("pypi", "Foo_Bar", null, null, null, "reviewed");

        assertThat(entry.name()).isEqualTo("foo-bar");
        assertThat(entry.covers("pypi", "foo-bar", "1.0", FINDING)).isTrue();
        assertThat(entry.covers("pypi", "foo.BAR", "1.0", FINDING)).isTrue();
        assertThat(entry.covers("pypi", "foobar", "1.0", FINDING)).isFalse();
    }

    @Test
    void npmAllowlistEntriesStayCaseSensitive() {
        AllowlistEntry entry = new AllowlistEntry("npm", "JSONStream", null, null, null, "reviewed");

        assertThat(entry.covers("npm", "JSONStream", "1.0.0", FINDING)).isTrue();
        assertThat(entry.covers("npm", "jsonstream", "1.0.0", FINDING)).isFalse();
    }
}
