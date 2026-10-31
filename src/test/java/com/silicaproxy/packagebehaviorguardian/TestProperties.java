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


package com.silicaproxy.packagebehaviorguardian;

import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.AllowlistEntry;
import java.util.List;

/** Hand-built properties for unit tests, mirroring the defaults of application.yaml. */
public final class TestProperties {

    private TestProperties() {
    }

    public static PackageBehaviorGuardianProperties defaults() {
        return withAllowlist(List.of());
    }

    public static PackageBehaviorGuardianProperties withAllowlist(List<AllowlistEntry> allowlist) {
        return build(allowlist, new PackageBehaviorGuardianProperties.RegistryProperties("https://pypi.org", List.of("files.pythonhosted.org")));
    }

    public static PackageBehaviorGuardianProperties withRegistries(PackageBehaviorGuardianProperties.RegistryProperties registries) {
        return build(List.of(), registries);
    }

    private static PackageBehaviorGuardianProperties build(List<AllowlistEntry> allowlist,
            PackageBehaviorGuardianProperties.RegistryProperties registries) {
        return new PackageBehaviorGuardianProperties(
                new PackageBehaviorGuardianProperties.SecurityProperties(true, "check-key", "report-key"),
                new PackageBehaviorGuardianProperties.IntakeProperties(
                        List.of("registry.npmjs.org", "files.pythonhosted.org", "silica.internal:8443", "localhost:*"),
                        List.of("silica.internal"), false, false),
                new PackageBehaviorGuardianProperties.ArtifactProperties(200, 60, null),
                registries,
                new PackageBehaviorGuardianProperties.QueueProperties(4, 3, 60, 30, 30),
                new PackageBehaviorGuardianProperties.CallbackProperties(11, 10, 300),
                new PackageBehaviorGuardianProperties.RetentionProperties(90),
                new PackageBehaviorGuardianProperties.AnalysisProperties("1", "https://pbg.internal/", 2, true, 30),
                new PackageBehaviorGuardianProperties.ScannerProperties(
                        new PackageBehaviorGuardianProperties.ToolProperties(true, List.of("guarddog"), 300),
                        new PackageBehaviorGuardianProperties.MalcontentProperties(true, List.of("mal"), 300, false),
                        new PackageBehaviorGuardianProperties.BytecodeProperties(true, List.of("org.projectlombok")),
                        new PackageBehaviorGuardianProperties.IsolationProperties(null, 64)),
                allowlist);
    }
}
