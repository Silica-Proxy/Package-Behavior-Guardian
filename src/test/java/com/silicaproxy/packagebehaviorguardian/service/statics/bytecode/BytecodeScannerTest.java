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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.silicaproxy.packagebehaviorguardian.TestJars;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BytecodeScannerTest {

    @TempDir
    Path tempDir;

    private final JarInspector inspector = new JarInspector(1000, 1024 * 1024);
    private final BytecodeRules rules = new BytecodeRules(List.of("org.projectlombok"));

    private List<Finding> scan(String groupId, Map<String, byte[]> entries) throws IOException {
        Path jar = tempDir.resolve("test.jar");
        Files.write(jar, TestJars.jar(entries));
        return rules.evaluate(inspector.inspect(jar), groupId);
    }

    @Test
    void execInAStaticInitializerIsCritical() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries(
                "com/evil/Init.class", TestJars.classWithExecInStaticInitializer("com/evil/Init")));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-001", Severity.CRITICAL));
        assertThat(findings.get(0).location()).isEqualTo("com/evil/Init#<clinit>");
    }

    @Test
    void execReachedFromAStaticInitializerThroughAHelperIsCritical() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries(
                "com/evil/Init.class", TestJars.classWithStaticInitializerCalling("com/evil/Init", "com/evil/Helper.run"),
                "com/evil/Helper.class",
                TestJars.classCalling("com/evil/Helper", "java/lang/Object", new String[] {"java/lang/Runtime.exec"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-001", Severity.CRITICAL));
        assertThat(findings.get(0).location()).isEqualTo("com/evil/Init#<clinit> via com/evil/Helper#run");
    }

    @Test
    void execInALambdaOfAStaticInitializerIsCritical() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries(
                "com/evil/Init.class", TestJars.classWithLambdaInStaticInitializer("com/evil/Init")));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-001", Severity.CRITICAL));
    }

    @Test
    void aBenignCopyOfAClassDoesNotHideItsMultiReleaseVariant() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries(
                "com/evil/Init.class", TestJars.classWithStaticInitializerCalling("com/evil/Init", "com/evil/Helper.run"),
                "META-INF/versions/17/com/evil/Helper.class",
                TestJars.classCalling("com/evil/Helper", "java/lang/Object", new String[] {"java/lang/Runtime.exec"}),
                "com/evil/Helper.class", TestJars.classCalling("com/evil/Helper", "java/lang/Object", new String[0])));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-001", Severity.CRITICAL));
    }

    @Test
    void aMojoDeclaredInPluginXmlCountsEvenWhenItsBaseClassIsInAnotherJar() throws IOException {
        List<Finding> findings = scan("org.example", TestJars.entries(
                "META-INF/maven/plugin.xml", "<plugin><mojos><mojo><implementation>org.example.RunMojo</implementation></mojo></mojos></plugin>",
                "org/example/RunMojo.class",
                TestJars.classCalling("org/example/RunMojo", "org/other/ExternalBaseMojo", new String[] {"java/lang/ProcessBuilder.start"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-001", Severity.MEDIUM));
    }

    @Test
    void aKnownPublisherPrefixOnlyCoversItsOwnSubGroups() throws IOException {
        Map<String, byte[]> processorJar = TestJars.entries(
                "META-INF/services/javax.annotation.processing.Processor", "lombok.Processor\n",
                "lombok/Processor.class", TestJars.classCalling("lombok/Processor", "java/lang/Object", new String[0]));

        assertThat(scan("org.projectlombok.extra", processorJar)).isEmpty();
        assertThat(scan("org.projectlombok-evil", processorJar)).extracting(Finding::ruleId).containsExactly("JVM-006");
    }

    @Test
    void reflectionOnProcessExecutionFromAStaticInitializerIsCritical() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries(
                "com/evil/Init.class", TestJars.classWithStaticInitializerCalling("com/evil/Init", "com/evil/Helper.run"),
                "com/evil/Helper.class", TestJars.classCalling("com/evil/Helper", "java/lang/Object",
                        new String[] {"java/lang/Class.forName", "java/lang/Class.getMethod", "java/lang/reflect/Method.invoke"},
                        "java.lang.Runtime", "exec")));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-007", Severity.CRITICAL));
    }

    @Test
    void reflectionOnDecodedNamesFromAStaticInitializerIsHigh() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries("com/evil/Init.class",
                TestJars.classWithStaticInitializerCalling("com/evil/Init", "com/evil/Loader.run"),
                "com/evil/Loader.class", TestJars.classCalling("com/evil/Loader", "java/lang/Object",
                        new String[] {"java/util/Base64$Decoder.decode", "java/lang/invoke/MethodHandles$Lookup.findStatic"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-007", Severity.HIGH));
    }

    @Test
    void plainReflectionInAStaticInitializerIsNotReported() throws IOException {
        // The everyday "is this optional dependency on the classpath?" probe of legitimate libraries.
        List<Finding> findings = scan("org.example", TestJars.entries(
                "org/example/Init.class", TestJars.classWithStaticInitializerCalling("org/example/Init", "org/example/Probe.run"),
                "org/example/Probe.class", TestJars.classCalling("org/example/Probe", "java/lang/Object",
                        new String[] {"java/lang/Class.forName", "java/lang/reflect/Method.invoke"}, "org.slf4j.LoggerFactory")));

        assertThat(findings).isEmpty();
    }

    @Test
    void anIndirectMojoSpawningThroughCommonsExecIsMedium() throws IOException {
        List<Finding> findings = scan("org.codehaus.mojo", TestJars.entries(
                "org/example/AbstractRunMojo.class",
                TestJars.classCalling("org/example/AbstractRunMojo", "org/apache/maven/plugin/AbstractMojo", new String[0]),
                "org/example/RunMojo.class",
                TestJars.classCalling("org/example/RunMojo", "org/example/AbstractRunMojo", new String[] {"org/example/MyExecutor.execute"}),
                "org/example/MyExecutor.class",
                TestJars.classCalling("org/example/MyExecutor", "org/apache/commons/exec/DefaultExecutor", new String[0])));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-001", Severity.MEDIUM));
        assertThat(findings.get(0).message()).contains("DefaultExecutor.execute");
    }

    @Test
    void execInAnOrdinaryMethodIsNotReported() throws IOException {
        List<Finding> findings = scan("com.example", TestJars.entries("com/example/Tool.class",
                TestJars.classCalling("com/example/Tool", "java/lang/Object", new String[] {"java/lang/Runtime.exec"})));

        assertThat(findings).isEmpty();
    }

    @Test
    void networkInAnAnnotationProcessorIsHigh() throws IOException {
        List<Finding> findings = scan("com.example", TestJars.entries(
                "META-INF/services/javax.annotation.processing.Processor", "# comment\ncom.example.Proc\n",
                "com/example/Proc.class",
                TestJars.classCalling("com/example/Proc", "java/lang/Object",
                        new String[] {"java/net/URL.<init>", "java/net/URL.openConnection"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity).containsExactlyInAnyOrder(
                org.assertj.core.groups.Tuple.tuple("JVM-003", Severity.HIGH),
                org.assertj.core.groups.Tuple.tuple("JVM-006", Severity.MEDIUM));
    }

    @Test
    void readingAResourceOfTheJarIsNotNetwork() throws IOException {
        List<Finding> findings = scan("org.projectlombok", TestJars.entries(
                "META-INF/services/javax.annotation.processing.Processor", "com.example.Proc\n",
                "com/example/Proc.class", TestJars.classCalling("com/example/Proc", "java/lang/Object",
                        new String[] {"java/lang/Class.getResource", "java/net/URL.openStream"})));

        assertThat(findings).isEmpty();
    }

    @Test
    void aKnownAnnotationProcessorPublisherIsNotReportedAsUnknown() throws IOException {
        List<Finding> findings = scan("org.projectlombok", TestJars.entries(
                "META-INF/services/javax.annotation.processing.Processor", "lombok.Processor\n",
                "lombok/Processor.class", TestJars.classCalling("lombok/Processor", "java/lang/Object", new String[0])));

        assertThat(findings).isEmpty();
    }

    @Test
    void execInAMojoIsOnlyMedium() throws IOException {
        List<Finding> findings = scan("org.example", TestJars.entries("org/example/RunMojo.class",
                TestJars.classCalling("org/example/RunMojo", "org/apache/maven/plugin/AbstractMojo",
                        new String[] {"java/lang/ProcessBuilder.start"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-001", Severity.MEDIUM));
    }

    @Test
    void definingAClassFromBase64DecodedBytesIsCritical() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries("com/evil/Loader.class",
                TestJars.classCalling("com/evil/Loader", "java/lang/ClassLoader",
                        new String[] {"java/util/Base64$Decoder.decode", "com/evil/Loader.defineClass"})));

        assertThat(findings).extracting(Finding::ruleId).containsExactly("JVM-002");
    }

    @Test
    void credentialPathsNextToUserHomeAreHigh() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries("com/evil/Steal.class",
                TestJars.classCalling("com/evil/Steal", "java/lang/Object", new String[0], "user.home", "/.aws/credentials")));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-004", Severity.HIGH));
    }

    @Test
    void anEmbeddedNativeLibraryThatIsLoadedIsMedium() throws IOException {
        List<Finding> findings = scan("com.example", TestJars.entries(
                "native/linux-x86_64/libfoo.so", new byte[] {0x7f, 'E', 'L', 'F'},
                "com/example/Native.class",
                TestJars.classCalling("com/example/Native", "java/lang/Object", new String[] {"java/lang/System.loadLibrary"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-005", Severity.MEDIUM));
    }

    @Test
    void aMalformedClassIsAHostileArtifactNotASkippedFile() {
        assertThatThrownBy(() -> scan("com.evil", TestJars.entries("com/evil/Broken.class", new byte[] {1, 2, 3})))
                .isInstanceOf(com.silicaproxy.packagebehaviorguardian.service.statics.HostileArtifactException.class);
    }

    @Test
    void anOversizedEntryFailsTheScan() {
        JarInspector strict = new JarInspector(1000, 10);
        assertThatThrownBy(() -> {
            Path jar = tempDir.resolve("big.jar");
            Files.write(jar, TestJars.jar(TestJars.entries("com/A.class", TestJars.classWithExecInStaticInitializer("com/A"))));
            strict.inspect(jar);
        }).isInstanceOf(IOException.class).hasMessageContaining("exceeds");
    }
}
