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


package com.silicaproxy.packagebehaviorguardian.service.statics.bytecode;

import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.BytecodeProperties;
import com.silicaproxy.packagebehaviorguardian.service.artifact.MavenLayout;
import com.silicaproxy.packagebehaviorguardian.service.statics.ScanContext;
import com.silicaproxy.packagebehaviorguardian.service.statics.StaticScanner;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

/** In-process ASM analysis of Maven jars (JVM-001 to JVM-007). Needs no external tool. */
@Component
@NullMarked
public class BytecodeScanner implements StaticScanner {

    // Zip-bomb guards: a jar beyond these limits fails the job.
    private static final int MAX_ENTRIES = 50_000;
    private static final long MAX_CLASS_SIZE_BYTES = 8L * 1024 * 1024;

    private final BytecodeProperties properties;
    private final JarInspector inspector;
    private final BytecodeRules rules;

    public BytecodeScanner(PackageBehaviorGuardianProperties properties) {
        this.properties = properties.scanners().bytecode();
        this.inspector = new JarInspector(MAX_ENTRIES, MAX_CLASS_SIZE_BYTES);
        this.rules = new BytecodeRules(this.properties.knownAnnotationProcessorGroups());
    }

    @Override
    public String name() {
        return BytecodeRules.SCANNER;
    }

    @Override
    public boolean enabled() {
        return properties.enabled();
    }

    @Override
    public boolean supports(String ecosystem) {
        return "maven".equals(ecosystem);
    }

    @Override
    public List<Finding> scan(ScanContext context) throws IOException {
        String groupId = MavenLayout.Coordinates.parse(context.name()).groupId();
        List<Finding> findings = new ArrayList<>();
        for (Path artifact : context.artifacts()) {
            if (String.valueOf(artifact.getFileName()).toLowerCase(Locale.ROOT).endsWith(".jar")) {
                findings.addAll(rules.evaluate(inspector.inspect(artifact), groupId));
            }
        }
        return findings;
    }
}
