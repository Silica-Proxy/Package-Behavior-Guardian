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

class MavenLayoutTest {

    private final MavenLayout.Coordinates coordinates = MavenLayout.Coordinates.parse("org.example.tools:my-lib");

    @Test
    void filesOfTheVersionAreDerivedFromTheRequestedUrlOnTheSameRepository() {
        URI pom = URI.create("https://silica.internal:8443/maven2/org/example/tools/my-lib/1.2.3/my-lib-1.2.3.pom");

        assertThat(MavenLayout.file(pom, coordinates, "1.2.3", "jar"))
                .hasToString("https://silica.internal:8443/maven2/org/example/tools/my-lib/1.2.3/my-lib-1.2.3.jar");
    }

    @Test
    void theMainArtifactFollowsThePackaging() {
        assertThat(MavenLayout.mainArtifactExtension("<project><packaging>pom</packaging></project>")).isEmpty();
        assertThat(MavenLayout.mainArtifactExtension("<project><packaging> aar </packaging></project>")).contains("aar");
        assertThat(MavenLayout.mainArtifactExtension("<project><packaging>maven-plugin</packaging></project>")).contains("jar");
        assertThat(MavenLayout.mainArtifactExtension("<project><artifactId>x</artifactId></project>")).contains("jar");
    }

    @Test
    void aCommentedOutPackagingIsIgnored() {
        assertThat(MavenLayout.mainArtifactExtension("<project><!-- <packaging>pom</packaging> --></project>")).contains("jar");
    }

    @Test
    void aUrlThatDoesNotMatchTheCoordinatesIsRefused() {
        URI other = URI.create("https://repo1.maven.org/maven2/org/other/lib/1.2.3/lib-1.2.3.pom");

        assertThatThrownBy(() -> MavenLayout.file(other, coordinates, "1.2.3", "jar")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void namesMustBeGroupIdColonArtifactId() {
        assertThatThrownBy(() -> MavenLayout.Coordinates.parse("no-colon")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MavenLayout.Coordinates.parse("a:b:c")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MavenLayout.Coordinates.parse(":b")).isInstanceOf(IllegalArgumentException.class);
    }
}
