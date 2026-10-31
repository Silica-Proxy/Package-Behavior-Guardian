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
    void aCredentialPathOnlyInAStringConcatenationRecipeIsHigh() throws IOException {
        // javac 9+ folds the constant part of `getProperty("user.home") + "/.aws/credentials"` into the
        // invokedynamic recipe: no ldc carries it.
        List<Finding> findings = scan("com.evil", TestJars.entries("com/evil/Steal.class",
                TestJars.classWithConcatInStaticInitializer("com/evil/Steal", "user.home", "/.aws/credentials")));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-004", Severity.HIGH));
    }

    @Test
    void execInAnImplementationOfAJarInterfaceCalledFromAStaticInitializerIsCritical() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries(
                "com/evil/Init.class", TestJars.classWithStaticInitializerCalling("com/evil/Init", "com/evil/Plugin.run"),
                "com/evil/Plugin.class", TestJars.interfaceWithRun("com/evil/Plugin"),
                "com/evil/EvilPlugin.class",
                TestJars.classImplementing("com/evil/EvilPlugin", "com/evil/Plugin", new String[] {"java/lang/Runtime.exec"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-001", Severity.CRITICAL));
        assertThat(findings.get(0).location()).isEqualTo("com/evil/Init#<clinit> via com/evil/EvilPlugin#run");
    }

    @Test
    void execInASubclassOverrideCalledThroughItsJarSuperclassIsCritical() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries(
                "com/evil/Init.class", TestJars.classWithStaticInitializerCalling("com/evil/Init", "com/evil/Task.run"),
                "com/evil/Task.class", TestJars.classCalling("com/evil/Task", "java/lang/Object", new String[0]),
                "com/evil/EvilTask.class",
                TestJars.classCalling("com/evil/EvilTask", "com/evil/Task", new String[] {"java/lang/Runtime.exec"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-001", Severity.CRITICAL));
    }

    @Test
    void anAnnotationProcessorDeclaredInModuleInfoIsRecognized() throws IOException {
        List<Finding> findings = scan("com.example", TestJars.entries(
                "module-info.class",
                TestJars.moduleInfoProviding("com.example", "javax/annotation/processing/Processor", "com/example/Proc"),
                "com/example/Proc.class",
                TestJars.classCalling("com/example/Proc", "java/lang/Object", new String[] {"java/lang/ProcessBuilder.start"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity).containsExactlyInAnyOrder(
                org.assertj.core.groups.Tuple.tuple("JVM-001", Severity.CRITICAL),
                org.assertj.core.groups.Tuple.tuple("JVM-006", Severity.MEDIUM));
        assertThat(findings).filteredOn(finding -> "JVM-006".equals(finding.ruleId()))
                .extracting(Finding::location).containsExactly("com/example/Proc");
    }

    @Test
    void aClassExtendingAbstractProcessorThroughAnotherJarClassIsAProcessor() throws IOException {
        List<Finding> findings = scan("com.example", TestJars.entries(
                "com/example/BaseProcessor.class",
                TestJars.classCalling("com/example/BaseProcessor", "javax/annotation/processing/AbstractProcessor", new String[0]),
                "com/example/Proc.class",
                TestJars.classCalling("com/example/Proc", "com/example/BaseProcessor", new String[] {"java/lang/Runtime.exec"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-001", Severity.CRITICAL));
        assertThat(findings.get(0).location()).isEqualTo("com/example/Proc#run");
    }

    @Test
    void aUrlBuiltByAHelperAndOpenedByTheProcessorIsNetwork() throws IOException {
        List<Finding> findings = scan("org.projectlombok", TestJars.entries(
                "META-INF/services/javax.annotation.processing.Processor", "com.example.Proc\n",
                "com/example/Proc.class", TestJars.classCalling("com/example/Proc", "java/lang/Object",
                        new String[] {"com/example/Urls.run", "java/net/URL.openConnection"}),
                "com/example/Urls.class",
                TestJars.classCalling("com/example/Urls", "java/lang/Object", new String[] {"java/net/URL.<init>"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-003", Severity.HIGH));
    }

    @Test
    void aUrlBuiltInAnotherMethodOfTheReadingClassIsNetwork() throws IOException {
        // Proc.run() { Http.fetch(Http.build()); }: the URL is built and opened by two sibling methods.
        List<Finding> findings = scan("org.projectlombok", TestJars.entries(
                "META-INF/services/javax.annotation.processing.Processor", "com.example.Proc\n",
                "com/example/Proc.class", TestJars.classCalling("com/example/Proc", "java/lang/Object",
                        new String[] {"com/example/Http.build", "com/example/Http.fetch"}),
                "com/example/Http.class", TestJars.classWithMethods("com/example/Http", Map.of(
                        "build", new String[] {"java/net/URL.<init>"}, "fetch", new String[] {"java/net/URL.openConnection"}))));

        assertThat(findings).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("JVM-003", Severity.HIGH));
        assertThat(findings.get(0).location()).isEqualTo("com/example/Proc#run via com/example/Http#fetch");
    }

    @Test
    void definingAClassFromBytesDecodedByAHelperIsCritical() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries(
                "com/evil/Loader.class", TestJars.classCalling("com/evil/Loader", "java/lang/ClassLoader",
                        new String[] {"com/evil/Decoder.run", "com/evil/Loader.defineClass"}),
                "com/evil/Decoder.class",
                TestJars.classCalling("com/evil/Decoder", "java/lang/Object", new String[] {"java/util/Base64$Decoder.decode"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::location).containsExactly(
                org.assertj.core.groups.Tuple.tuple("JVM-002", "com/evil/Loader#run"));
    }

    @Test
    void decodedBytesHandedOverToAnotherClassThatDefinesThemAreCritical() throws IOException {
        List<Finding> findings = scan("com.evil", TestJars.entries(
                "com/evil/Stage.class", TestJars.classCalling("com/evil/Stage", "java/lang/Object",
                        new String[] {"java/util/Base64$Decoder.decode", "com/evil/Loader.run"}),
                "com/evil/Loader.class",
                TestJars.classCalling("com/evil/Loader", "java/lang/ClassLoader", new String[] {"com/evil/Loader.defineClass"})));

        assertThat(findings).extracting(Finding::ruleId, Finding::location).containsExactly(
                org.assertj.core.groups.Tuple.tuple("JVM-002", "com/evil/Stage#run via com/evil/Loader#run"));
    }

    @Test
    void aClassGeneratorReachingAnXorElsewhereIsNotReported() throws IOException {
        // A hashCode() XORing in a class the defining method happens to reach is not a decoder.
        List<Finding> findings = scan("net.bytebuddy", TestJars.entries(
                "net/bytebuddy/Injector.class", TestJars.classCalling("net/bytebuddy/Injector", "java/lang/ClassLoader",
                        new String[] {"net/bytebuddy/Key.run", "net/bytebuddy/Injector.defineClass"}),
                "net/bytebuddy/Key.class", TestJars.classWithXor("net/bytebuddy/Key")));

        assertThat(findings).isEmpty();
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
