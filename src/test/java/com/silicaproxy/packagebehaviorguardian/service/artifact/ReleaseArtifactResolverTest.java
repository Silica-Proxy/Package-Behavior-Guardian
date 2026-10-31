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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.silicaproxy.packagebehaviorguardian.TestProperties;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.JobStatus;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.RegistryProperties;
import com.silicaproxy.packagebehaviorguardian.service.intake.UrlPolicy;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** PyPI versions are listed by registries.pypi-url's JSON API: only files of that index may be checked. */
class ReleaseArtifactResolverTest {

    private static final String WHEEL = "https://files.pythonhosted.org/packages/ab/cd/foo_bar-1.0-py3-none-any.whl";
    private static final String SDIST = "https://files.pythonhosted.org/packages/ab/cd/foo_bar-1.0.tar.gz";

    private final RegistryClient registryClient = mock(RegistryClient.class);
    private final ArtifactDownloader downloader = mock(ArtifactDownloader.class);

    private ReleaseArtifactResolver resolver(RegistryProperties registries) {
        PackageBehaviorGuardianProperties properties = TestProperties.withRegistries(registries);
        return new ReleaseArtifactResolver(registryClient, downloader, new UrlPolicy(properties), properties);
    }

    private static AnalysisJob pypiJob(String url) {
        return new AnalysisJob(UUID.randomUUID(), "pypi", "foo-bar", "1.0", url, JobStatus.RUNNING, 1, null, Instant.now());
    }

    @Test
    void filesOfThePypiIndexAreAcceptedAndTheWholeVersionIsListed() throws IOException {
        ReleaseArtifactResolver resolver = resolver(new RegistryProperties("https://pypi.org", List.of("files.pythonhosted.org")));
        when(registryClient.pypiVersionFiles("foo-bar", "1.0")).thenReturn(List.of(WHEEL, SDIST));

        assertThatCode(() -> resolver.requireListedHost("pypi", URI.create(WHEEL))).doesNotThrowAnyException();
        assertThatCode(() -> resolver.requireListedHost("pypi", URI.create("https://pypi.org/packages/foo_bar-1.0.tar.gz")))
                .doesNotThrowAnyException();
        assertThat(resolver.resolve(pypiJob(WHEEL)).files()).containsExactly(URI.create(WHEEL), URI.create(SDIST));
    }

    @Test
    void aPypiFileFromAnotherIndexIsRefusedRatherThanListedFromPypiOrg() {
        // silica.internal:8443 is an allowed artifact host, but pypi.org's list would describe another package.
        ReleaseArtifactResolver resolver = resolver(new RegistryProperties("https://pypi.org", List.of("files.pythonhosted.org")));
        String mirrored = "https://silica.internal:8443/pypi/packages/foo_bar-1.0.tar.gz";

        assertThatThrownBy(() -> resolver.requireListedHost("pypi", URI.create(mirrored)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("silica.internal:8443");
        assertThatThrownBy(() -> resolver.resolve(pypiJob(mirrored))).isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(registryClient);
    }

    @Test
    void aMirrorIsUsableOnceItsApiAndFileHostAreConfigured() throws IOException {
        ReleaseArtifactResolver resolver = resolver(new RegistryProperties("https://silica.internal:8443/pypi", List.of()));
        String mirrored = "https://silica.internal:8443/pypi/packages/foo_bar-1.0.tar.gz";
        when(registryClient.pypiVersionFiles(any(), any())).thenReturn(List.of(mirrored));

        assertThat(resolver.resolve(pypiJob(mirrored)).files()).containsExactly(URI.create(mirrored));
        verify(registryClient).pypiVersionFiles("foo-bar", "1.0");
        assertThatThrownBy(() -> resolver.requireListedHost("pypi", URI.create(WHEEL))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void otherEcosystemsAreNotBoundToThePypiIndex() {
        ReleaseArtifactResolver resolver = resolver(new RegistryProperties("https://pypi.org", List.of("files.pythonhosted.org")));

        assertThatCode(() -> resolver.requireListedHost("npm", URI.create("https://registry.npmjs.org/a/-/a-1.0.0.tgz")))
                .doesNotThrowAnyException();
    }
}
