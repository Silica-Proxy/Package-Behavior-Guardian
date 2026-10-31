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

import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.service.statics.bytecode.JarFacts.Call;
import com.silicaproxy.packagebehaviorguardian.service.statics.bytecode.JarFacts.ClassFacts;
import com.silicaproxy.packagebehaviorguardian.service.statics.bytecode.JarFacts.MethodFacts;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The memoized {@link CallGraph} must answer exactly what an uncached breadth-first walk answers
 * (same calls in the same order, same constants), on graphs with cycles and shared subgraphs, and
 * stay fast on large synthetic graphs.
 */
class CallGraphTest {

    private static final String EXEC = "java/lang/Runtime.exec";

    @Test
    void cycleIsWalkedOnceAndCachedResultsMatchAFreshWalk() {
        // A -> B -> C -> A, C -> exec: every method of the cycle reaches the exec, whatever the query order.
        JarFacts jar = jar(type("p/A", null, method("a", "p/B.b")),
                type("p/B", null, method("b", "p/C.c")),
                type("p/C", null, method("c", "p/A.a", EXEC)));
        CallGraph graph = new CallGraph(jar);
        for (String start : List.of("c", "a", "b", "a", "c")) {
            CallGraph.Reach reach = graph.reachFrom(find(jar, start));
            assertThat(reach.calls()).extracting(call -> call.call().owner() + "." + call.call().name()).containsExactly(EXEC);
            assertThat(reach.calls()).extracting(CallGraph.ExternalCall::fromClass).containsExactly("p/C");
        }
        assertSameAsReference(jar);
    }

    @Test
    void sharedSubgraphIsReportedFromEveryCaller() {
        // Diamond: top -> left, right -> shared -> exec; a second root also reaches shared.
        JarFacts jar = jar(type("p/D", null,
                method("top", "p/D.left", "p/D.right"), method("left", "p/D.shared"), method("right", "p/D.shared"),
                method("other", "p/D.shared"), method("shared", EXEC)));
        CallGraph graph = new CallGraph(jar);
        assertThat(graph.reachFrom(find(jar, "shared")).calls()).hasSize(1);
        assertThat(graph.reachFrom(find(jar, "top")).calls()).hasSize(1);
        assertThat(graph.reachFrom(find(jar, "other")).calls()).hasSize(1);
        assertSameAsReference(jar);
    }

    @Test
    void depthBoundDependsOnTheStartNotOnWhatWasCachedBefore() {
        // A chain longer than the depth bound: a cached deep method must not leak its reach into a shallower query.
        List<MethodFacts> chain = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            chain.add(i == 11 ? method("m" + i, EXEC) : method("m" + i, "p/L.m" + (i + 1)));
        }
        JarFacts jar = jar(new ClassFacts("p/L", null, List.of(), chain));
        CallGraph graph = new CallGraph(jar);
        assertThat(graph.reachFrom(find(jar, "m11")).calls()).hasSize(1);
        assertThat(graph.reachFrom(find(jar, "m5")).calls()).hasSize(1);
        assertThat(graph.reachFrom(find(jar, "m0")).calls()).isEmpty();
        assertSameAsReference(jar);
    }

    @Test
    void randomGraphsWithCyclesMatchTheUncachedWalk() {
        Random random = new Random(42);
        for (int round = 0; round < 50; round++) {
            assertSameAsReference(randomJar(random, 3 + random.nextInt(6), 2 + random.nextInt(15)));
        }
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void layeredDiamondOfThousandsOfMethodsIsFast() {
        // 100 layers x 20 methods, each calling every method of the next layer, all in one Mojo
        // class, closed into a cycle: every method is a start and every walk hits the size bounds.
        int layers = 100;
        int width = 20;
        List<MethodFacts> methods = new ArrayList<>();
        for (int layer = 0; layer < layers; layer++) {
            for (int i = 0; i < width; i++) {
                List<Call> calls = new ArrayList<>();
                for (int j = 0; j < width; j++) {
                    calls.add(new Call("p/Big", "m" + ((layer + 1) % layers) + "_" + j));
                }
                if (layer % 10 == 9 && i == 0) {
                    calls.add(new Call("java/lang/Runtime", "exec"));
                }
                methods.add(new MethodFacts("m" + layer + "_" + i, calls, List.of("s" + layer), false));
            }
        }
        JarFacts jar = new JarFacts(List.of(new ClassFacts("p/Big", "org/apache/maven/plugin/AbstractMojo", List.of(), methods)),
                Set.of(), List.of(), Set.of("p/Big"));
        List<Finding> findings = new BytecodeRules(List.of()).evaluate(jar, "p");
        assertThat(findings).extracting(Finding::ruleId).contains("JVM-001");
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void longChainAcrossThousandsOfClassesIsFast() {
        // 5000 classes, each with a static initializer calling the next class, and a big sibling class with many methods.
        int size = 5000;
        List<ClassFacts> types = new ArrayList<>();
        List<MethodFacts> helpers = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            String next = "p/C" + ((i + 1) % size);
            types.add(type("p/C" + i, i % 2 == 0 ? null : "p/C" + (i - 1),
                    method("<clinit>", next + ".<clinit>", "p/H.h" + i), method("run", next + ".run")));
            helpers.add(i % 1000 == 999 ? method("h" + i, EXEC) : method("h" + i, "p/H.h" + ((i + 1) % size)));
        }
        types.add(new ClassFacts("p/H", null, List.of(), helpers));
        JarFacts jar = new JarFacts(types, Set.of(), List.of(), Set.of());
        List<Finding> findings = new BytecodeRules(List.of()).evaluate(jar, "p");
        assertThat(findings).extracting(Finding::ruleId).contains("JVM-001");
    }

    private static void assertSameAsReference(JarFacts jar) {
        List<MethodFacts> all = jar.classes().stream().flatMap(type -> type.methods().stream()).toList();
        CallGraph graph = new CallGraph(jar);
        List<MethodFacts> order = new ArrayList<>(all);
        Collections.shuffle(order, new Random(all.size()));
        order.addAll(all);
        for (MethodFacts start : order) {
            CallGraph.Reach expected = referenceReach(jar, start);
            CallGraph.Reach actual = graph.reachFrom(start);
            assertThat(actual.calls()).as("calls from %s", start.name()).containsExactlyElementsOf(expected.calls());
            assertThat(actual.strings()).as("strings from %s", start.name()).isEqualTo(expected.strings());
            assertThat(actual.usesXor()).as("xor from %s", start.name()).isEqualTo(expected.usesXor());
        }
    }

    private static JarFacts randomJar(Random random, int classCount, int methodsPerClass) {
        List<ClassFacts> types = new ArrayList<>();
        for (int c = 0; c < classCount; c++) {
            List<MethodFacts> methods = new ArrayList<>();
            for (int m = 0; m < methodsPerClass; m++) {
                List<Call> calls = new ArrayList<>();
                int callCount = random.nextInt(4);
                for (int k = 0; k < callCount; k++) {
                    calls.add(random.nextInt(5) == 0
                            ? new Call("ext/E" + random.nextInt(3), "x" + random.nextInt(3))
                            : new Call("r/C" + random.nextInt(classCount + 1), "m" + random.nextInt(methodsPerClass + 1)));
                }
                methods.add(new MethodFacts("m" + random.nextInt(methodsPerClass), calls,
                        List.of("s" + random.nextInt(10)), random.nextInt(10) == 0));
            }
            String superName = c > 0 && random.nextBoolean() ? "r/C" + random.nextInt(c) : random.nextBoolean() ? "ext/Base" : null;
            types.add(new ClassFacts("r/C" + c, superName, List.of(), methods));
        }
        return new JarFacts(types, Set.of(), List.of(), Set.of());
    }

    // The walk CallGraph did before memoization, kept verbatim as the oracle.
    private static CallGraph.Reach referenceReach(JarFacts jar, MethodFacts start) {
        Map<String, ClassFacts> classes = new HashMap<>();
        Map<MethodFacts, String> ownerOf = new IdentityHashMap<>();
        Map<String, Set<String>> directSubtypes = new HashMap<>();
        for (ClassFacts type : jar.classes()) {
            classes.merge(type.name(), type, (first, second) -> new ClassFacts(first.name(), first.superName(), first.interfaces(),
                    java.util.stream.Stream.concat(first.methods().stream(), second.methods().stream()).toList()));
            type.methods().forEach(method -> ownerOf.put(method, type.name()));
            if (type.superName() != null) {
                directSubtypes.computeIfAbsent(type.superName(), key -> new HashSet<>()).add(type.name());
            }
            type.interfaces().forEach(name -> directSubtypes.computeIfAbsent(name, key -> new HashSet<>()).add(type.name()));
        }
        List<CallGraph.ExternalCall> result = new ArrayList<>();
        Set<String> strings = new HashSet<>();
        boolean usesXor = false;
        Set<MethodFacts> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<MethodFacts> current = new ArrayDeque<>(List.of(start));
        visited.add(start);
        for (int depth = 0; depth <= 6 && !current.isEmpty(); depth++) {
            Deque<MethodFacts> next = new ArrayDeque<>();
            for (MethodFacts method : current) {
                strings.addAll(method.strings());
                usesXor |= method.usesXor();
                for (Call call : method.calls()) {
                    List<MethodFacts> targets = new ArrayList<>(referenceResolve(classes, call));
                    if (targets.isEmpty()) {
                        result.add(new CallGraph.ExternalCall(new Call(referenceExternalOwner(classes, call.owner()), call.name()),
                                ownerOf.getOrDefault(method, "?"), method.name()));
                    }
                    targets.addAll(referenceOverriders(classes, directSubtypes, call));
                    for (MethodFacts target : targets) {
                        if (visited.size() < 2000 && visited.add(target)) {
                            next.add(target);
                        }
                    }
                }
            }
            current = next;
        }
        return new CallGraph.Reach(result, strings, usesXor);
    }

    private static List<MethodFacts> referenceResolve(Map<String, ClassFacts> classes, Call call) {
        Set<String> seen = new HashSet<>();
        String current = call.owner();
        while (current != null && seen.add(current)) {
            ClassFacts type = classes.get(current);
            if (type == null) {
                return List.of();
            }
            List<MethodFacts> found = type.methods().stream().filter(method -> method.name().equals(call.name())).toList();
            if (!found.isEmpty()) {
                return found;
            }
            current = type.superName();
        }
        return List.of();
    }

    private static List<MethodFacts> referenceOverriders(Map<String, ClassFacts> classes, Map<String, Set<String>> directSubtypes,
            Call call) {
        if (call.name().startsWith("<") || !classes.containsKey(call.owner())) {
            return List.of();
        }
        List<MethodFacts> found = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Deque<String> pending = new ArrayDeque<>(directSubtypes.getOrDefault(call.owner(), Set.of()));
        while (!pending.isEmpty() && found.size() < 2000) {
            String subtype = pending.pop();
            if (seen.add(subtype)) {
                ClassFacts type = classes.get(subtype);
                if (type != null) {
                    type.methods().stream().filter(method -> method.name().equals(call.name())).forEach(found::add);
                }
                pending.addAll(directSubtypes.getOrDefault(subtype, Set.of()));
            }
        }
        return found;
    }

    private static String referenceExternalOwner(Map<String, ClassFacts> classes, String owner) {
        Set<String> seen = new HashSet<>();
        String current = owner;
        while (seen.add(current)) {
            ClassFacts type = classes.get(current);
            String parent = type == null ? null : type.superName();
            if (type == null || parent == null) {
                return current;
            }
            current = parent;
        }
        return current;
    }

    private static MethodFacts find(JarFacts jar, String name) {
        return jar.classes().stream().flatMap(type -> type.methods().stream())
                .filter(method -> method.name().equals(name)).findFirst().orElseThrow();
    }

    private static JarFacts jar(ClassFacts... types) {
        return new JarFacts(List.of(types), Set.of(), List.of(), Set.of());
    }

    private static ClassFacts type(String name, String superName, MethodFacts... methods) {
        return new ClassFacts(name, superName, List.of(), List.of(methods));
    }

    // Each call is "owner.name".
    private static MethodFacts method(String name, String... calls) {
        List<Call> parsed = new ArrayList<>();
        for (String call : calls) {
            int dot = call.lastIndexOf('.');
            parsed.add(new Call(call.substring(0, dot), call.substring(dot + 1)));
        }
        return new MethodFacts(name, parsed, List.of(), false);
    }
}
