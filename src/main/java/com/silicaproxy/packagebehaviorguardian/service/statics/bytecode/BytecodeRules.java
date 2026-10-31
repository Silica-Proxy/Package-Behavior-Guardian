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
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import com.silicaproxy.packagebehaviorguardian.service.statics.Texts;
import com.silicaproxy.packagebehaviorguardian.service.statics.bytecode.JarFacts.Call;
import com.silicaproxy.packagebehaviorguardian.service.statics.bytecode.JarFacts.ClassFacts;
import com.silicaproxy.packagebehaviorguardian.service.statics.bytecode.JarFacts.MethodFacts;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NullMarked;

/**
 * Rules JVM-001 to JVM-007. Code runs without the application calling it in three places: a
 * static initializer ({@code <clinit>}), an annotation processor (at compile time, on developer
 * machines and CI) and a Maven plugin Mojo (during the build). Exec and network calls reachable
 * from there, through the jar's own classes ({@link CallGraph}), are what JVM-001/003 look for. A
 * Mojo legitimately spawns processes and downloads (exec-maven-plugin, frontend-maven-plugin), so
 * in a Mojo those two rules only report MEDIUM, while a static initializer or a processor reports
 * CRITICAL/HIGH.
 */
@NullMarked
public final class BytecodeRules {

    public static final String SCANNER = "bytecode";
    private static final int MAX_FINDINGS_PER_RULE = 10;
    private static final List<String> SENSITIVE_PATHS = List.of(
            ".ssh", ".aws", ".m2/settings.xml", "settings-security.xml", ".npmrc", ".pypirc", ".docker/config.json",
            ".kube/config", ".git-credentials", ".config/gh", ".gnupg");

    private static final Set<Call> EXEC_CALLS = Set.of(
            new Call("java/lang/Runtime", "exec"), new Call("java/lang/ProcessBuilder", "start"),
            new Call("org/apache/commons/exec/DefaultExecutor", "execute"), new Call("org/apache/commons/exec/Executor", "execute"));
    private static final Set<Call> NETWORK_CALLS = Set.of(
            new Call("java/net/URL", "openConnection"), new Call("java/net/URL", "openStream"), new Call("java/net/Socket", "<init>"),
            new Call("java/net/http/HttpClient", "send"), new Call("java/net/http/HttpClient", "sendAsync"),
            new Call("java/net/InetAddress", "getByName"));
    private static final Set<Call> REFLECTIVE_CALLS = Set.of(
            new Call("java/lang/reflect/Method", "invoke"), new Call("java/lang/invoke/MethodHandle", "invoke"),
            new Call("java/lang/invoke/MethodHandle", "invokeExact"), new Call("java/lang/invoke/MethodHandle", "invokeWithArguments"),
            new Call("java/lang/invoke/MethodHandles$Lookup", "findVirtual"), new Call("java/lang/invoke/MethodHandles$Lookup", "findStatic"),
            new Call("java/lang/invoke/MethodHandles$Lookup", "findConstructor"));
    private static final Set<String> EXEC_NAMES = Set.of(
            "java.lang.Runtime", "java/lang/Runtime", "java.lang.ProcessBuilder", "java/lang/ProcessBuilder", "exec");
    private static final Call BASE64_DECODE = new Call("java/util/Base64$Decoder", "decode");
    private static final Set<Call> URL_READS = Set.of(new Call("java/net/URL", "openConnection"), new Call("java/net/URL", "openStream"));
    private static final Set<Call> URL_BUILDERS = Set.of(new Call("java/net/URL", "<init>"), new Call("java/net/URI", "toURL"));
    private static final Call URL_CLASS_LOADER = new Call("java/net/URLClassLoader", "<init>");
    private static final String PROCESSOR_BASE = "javax/annotation/processing/AbstractProcessor";
    private static final String PROCESSOR_INTERFACE = "javax/annotation/processing/Processor";

    private final List<String> knownAnnotationProcessorGroups;

    public BytecodeRules(List<String> knownAnnotationProcessorGroups) {
        this.knownAnnotationProcessorGroups = List.copyOf(knownAnnotationProcessorGroups);
    }

    public List<Finding> evaluate(JarFacts jar, String groupId) {
        Map<String, List<Finding>> byRule = new HashMap<>();
        CallGraph graph = new CallGraph(jar);
        for (ClassFacts type : jar.classes()) {
            String context = contextOf(type, jar, graph);
            boolean mojo = jar.pluginMojos().contains(type.name())
                    || graph.inherits(type.name(), "org/apache/maven/plugin/AbstractMojo", "org/apache/maven/plugin/Mojo");
            for (MethodFacts method : type.methods()) {
                String location = type.name() + "#" + method.name();
                String methodContext = "<clinit>".equals(method.name()) ? "a static initializer" : context;
                if (!methodContext.isEmpty() || mojo) {
                    CallGraph.Reach reach = graph.reachFrom(method);
                    execAndNetwork(graph, reach.calls(), methodContext, location, byRule);
                    reflection(reach, methodContext, location, byRule);
                }
                classLoading(graph, method, location, byRule);
            }
            sensitivePaths(type, byRule);
        }
        nativeLibraries(jar, byRule);
        annotationProcessors(jar, groupId, byRule);
        List<Finding> findings = new ArrayList<>();
        byRule.values().forEach(findings::addAll);
        return findings;
    }

    // "" = ordinary class: exec/network there are not reported (the application
    // decides when to call them). A processor is declared (services file, module-info) or inherits
    // AbstractProcessor / Processor, possibly through other jar classes: a base class shared by the
    // declared processors runs at compile time too.
    private static String contextOf(ClassFacts type, JarFacts jar, CallGraph graph) {
        if (jar.annotationProcessors().contains(type.name()) || graph.inherits(type.name(), PROCESSOR_BASE, PROCESSOR_INTERFACE)) {
            return "an annotation processor";
        }
        return "";
    }

    // An empty context means a Mojo method (the only other case the caller passes in).
    private static void execAndNetwork(CallGraph graph, List<CallGraph.ExternalCall> calls, String context, String location,
            Map<String, List<Finding>> byRule) {
        CallGraph.ExternalCall exec = calls.stream().filter(call -> EXEC_CALLS.contains(call.call())).findFirst().orElse(null);
        CallGraph.ExternalCall network = calls.stream()
                .filter(call -> NETWORK_CALLS.contains(call.call()) && (!URL_READS.contains(call.call()) || buildsUrl(graph, calls, call)))
                .findFirst().orElse(null);
        boolean sensitive = !context.isEmpty();
        String where = sensitive ? context : "a Maven Mojo";
        if (exec != null) {
            add(byRule, "JVM-001", sensitive ? Severity.CRITICAL : Severity.MEDIUM,
                    "Process execution (" + simpleName(exec) + ") reachable from " + where, location + via(exec, location));
        }
        if (network != null) {
            add(byRule, "JVM-003", sensitive ? Severity.HIGH : Severity.MEDIUM,
                    "Network call (" + simpleName(network) + ") reachable from " + where, location + via(network, location));
        }
    }

    // JVM-007: a reflective call (Method.invoke, MethodHandle.invoke*, Lookup.find*) reachable from
    // code that runs by itself sidesteps JVM-001..003 -- Class.forName("java.lang.Runtime")
    // .getMethod("exec", ...).invoke(...). Reflection alone is everywhere in legitimate libraries (optional
    // dependencies, compatibility shims), so only two shapes are reported: the process-execution
    // names in clear (same severity as JVM-001), or names decoded at run time (Base64 / XOR).
    private static void reflection(CallGraph.Reach reach, String context, String location, Map<String, List<Finding>> byRule) {
        boolean reflects = reach.calls().stream().anyMatch(call -> REFLECTIVE_CALLS.contains(call.call()));
        if (!reflects) {
            return;
        }
        boolean sensitive = !context.isEmpty();
        String where = sensitive ? context : "a Maven Mojo";
        if (reach.strings().stream().anyMatch(EXEC_NAMES::contains)) {
            add(byRule, "JVM-007", sensitive ? Severity.CRITICAL : Severity.MEDIUM,
                    "Reflective call to process execution reachable from " + where, location);
        } else if (reach.usesXor() || reach.calls().stream().anyMatch(call -> BASE64_DECODE.equals(call.call()))) {
            add(byRule, "JVM-007", sensitive ? Severity.HIGH : Severity.MEDIUM,
                    "Reflective call on names decoded at run time (Base64 / XOR) reachable from " + where, location);
        }
    }

    // URL.openStream/openConnection on a URL from getResource() reads the jar itself: it only counts
    // as network when the URL is built (new URL(...) / URI.toURL()) by the reading class, or by a
    // method the reading method calls (a helper returning the URL). A URL built anywhere else in the
    // reach is not enough: processors and Mojos read their own resources and build unrelated URLs.
    private static boolean buildsUrl(CallGraph graph, List<CallGraph.ExternalCall> calls, CallGraph.ExternalCall read) {
        if (calls.stream().anyMatch(call -> URL_BUILDERS.contains(call.call()) && call.fromClass().equals(read.fromClass()))) {
            return true;
        }
        return graph.declared(read.fromClass(), read.fromMethod()).stream().anyMatch(method ->
                graph.reachFrom(method).calls().stream().anyMatch(call -> URL_BUILDERS.contains(call.call())));
    }

    private static String simpleName(CallGraph.ExternalCall call) {
        String owner = call.call().owner();
        return owner.substring(owner.lastIndexOf('/') + 1) + "." + call.call().name();
    }

    private static String via(CallGraph.ExternalCall call, String location) {
        String from = call.fromClass() + "#" + call.fromMethod();
        return from.equals(location) ? "" : " via " + from;
    }

    // JVM-002. The bytes may be decoded by a helper the defining method calls, or by a method that
    // hands them over to the defining one: Base64 decoding is followed through the call graph in both
    // directions. XOR only counts in the defining method itself -- hash codes XOR everywhere, and a
    // class-generating library (ByteBuddy, Javassist) would reach one.
    private static void classLoading(CallGraph graph, MethodFacts method, String location, Map<String, List<Finding>> byRule) {
        boolean defines = method.callsNamed("defineClass") || method.callsNamed("defineHiddenClass")
                || method.calls(URL_CLASS_LOADER.owner(), URL_CLASS_LOADER.name());
        boolean decodes = method.calls(BASE64_DECODE.owner(), BASE64_DECODE.name());
        String message = "Defines classes from decoded bytes (Base64 / XOR)";
        if (defines) {
            if (decodes || method.usesXor() || graph.reachFrom(method).calls().stream().anyMatch(call -> BASE64_DECODE.equals(call.call()))) {
                add(byRule, "JVM-002", Severity.CRITICAL, message, location);
            }
        } else if (decodes) {
            graph.reachFrom(method).calls().stream().filter(BytecodeRules::definesClasses).findFirst()
                    .ifPresent(define -> add(byRule, "JVM-002", Severity.CRITICAL, message, location + via(define, location)));
        }
    }

    private static boolean definesClasses(CallGraph.ExternalCall call) {
        String name = call.call().name();
        return "defineClass".equals(name) || "defineHiddenClass".equals(name) || URL_CLASS_LOADER.equals(call.call());
    }

    private static void sensitivePaths(ClassFacts type, Map<String, List<Finding>> byRule) {
        Set<String> strings = new LinkedHashSet<>();
        type.methods().forEach(method -> strings.addAll(method.strings()));
        if (!strings.contains("user.home")) {
            return;
        }
        SENSITIVE_PATHS.stream()
                .filter(path -> strings.stream().anyMatch(value -> value.contains(path)))
                .findFirst()
                .ifPresent(path -> add(byRule, "JVM-004", Severity.HIGH,
                        "Reads user.home and refers to a credential path (" + path + ")", type.name()));
    }

    private static void nativeLibraries(JarFacts jar, Map<String, List<Finding>> byRule) {
        boolean loads = jar.classes().stream().flatMap(type -> type.methods().stream()).anyMatch(method ->
                method.calls("java/lang/System", "load") || method.calls("java/lang/System", "loadLibrary")
                        || method.calls("java/lang/Runtime", "load") || method.calls("java/lang/Runtime", "loadLibrary"));
        if (loads && !jar.nativeLibraries().isEmpty()) {
            add(byRule, "JVM-005", Severity.MEDIUM, "Embeds a native library and loads native code", jar.nativeLibraries().get(0));
        }
    }

    private void annotationProcessors(JarFacts jar, String groupId, Map<String, List<Finding>> byRule) {
        boolean known = knownAnnotationProcessorGroups.stream()
                .anyMatch(prefix -> groupId.equals(prefix) || groupId.startsWith(prefix + "."));
        if (!jar.annotationProcessors().isEmpty() && !known) {
            add(byRule, "JVM-006", Severity.MEDIUM, "Declares an annotation processor (runs at compile time)",
                    String.join(", ", jar.annotationProcessors()));
        }
    }

    private static void add(Map<String, List<Finding>> byRule, String ruleId, Severity severity, String message, String location) {
        List<Finding> findings = byRule.computeIfAbsent(ruleId, key -> new ArrayList<>());
        if (findings.size() < MAX_FINDINGS_PER_RULE) {
            findings.add(new Finding(ruleId, severity, SCANNER, message, Texts.clip(location)));
        }
    }
}
