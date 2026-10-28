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
import java.util.Set;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * Calls reachable from a method through the jar's own classes. A payload is rarely written inside
 * {@code <clinit>} itself: {@code static { Helper.run(); }} with the exec in {@code Helper} is the
 * usual shape, and a Mojo spawns processes through a helper class. Calls are resolved by owner and
 * name (descriptors ignored: overloads are merged, which can only over-report) along the in-jar
 * superclass chain; calls leaving the jar are terminal and reported with the first non-jar class
 * of that chain as owner, so {@code MyExecutor.execute} on a {@code DefaultExecutor} subclass reads
 * as {@code DefaultExecutor.execute}. The walk is bounded in depth and size: hostile jars can build
 * arbitrarily large graphs.
 */
@NullMarked
final class CallGraph {

    private static final int MAX_DEPTH = 6;
    private static final int MAX_METHODS = 2000;

    /** A call leaving the jar, and the in-jar method that makes it. */
    record ExternalCall(Call call, String fromClass, String fromMethod) {
    }

    /** What a method can reach: calls leaving the jar, string constants, and whether any reached method XORs. */
    record Reach(List<ExternalCall> calls, Set<String> strings, boolean usesXor) {
    }

    private final Map<String, ClassFacts> classes = new HashMap<>();
    private final Map<MethodFacts, String> ownerOf = new IdentityHashMap<>();

    CallGraph(JarFacts jar) {
        for (ClassFacts type : jar.classes()) {
            // A Multi-Release jar (META-INF/versions/N/...) or duplicate zip entries can hold several
            // classes of one name: their methods are merged, so a benign copy cannot hide another.
            classes.merge(type.name(), type, (first, second) -> new ClassFacts(first.name(), first.superName(), first.interfaces(),
                    java.util.stream.Stream.concat(first.methods().stream(), second.methods().stream()).toList()));
            type.methods().forEach(method -> ownerOf.put(method, type.name()));
        }
    }

    /** Everything reachable from {@code start}, including its own calls and constants. */
    Reach reachFrom(MethodFacts start) {
        List<ExternalCall> result = new ArrayList<>();
        Set<String> strings = new HashSet<>();
        boolean usesXor = false;
        Set<MethodFacts> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<MethodFacts> current = new ArrayDeque<>(List.of(start));
        visited.add(start);
        for (int depth = 0; depth <= MAX_DEPTH && !current.isEmpty(); depth++) {
            Deque<MethodFacts> next = new ArrayDeque<>();
            for (MethodFacts method : current) {
                strings.addAll(method.strings());
                usesXor |= method.usesXor();
                for (Call call : method.calls()) {
                    List<MethodFacts> targets = resolve(call);
                    if (targets.isEmpty()) {
                        result.add(new ExternalCall(new Call(externalOwner(call.owner()), call.name()),
                                ownerOf.getOrDefault(method, "?"), method.name()));
                    }
                    for (MethodFacts target : targets) {
                        if (visited.size() < MAX_METHODS && visited.add(target)) {
                            next.add(target);
                        }
                    }
                }
            }
            current = next;
        }
        return new Reach(result, strings, usesXor);
    }

    /** True if {@code className} extends {@code superName} or implements {@code interfaceName}, directly or through jar classes. */
    boolean inherits(String className, String superName, String interfaceName) {
        Set<String> seen = new HashSet<>();
        String current = className;
        while (current != null && seen.add(current)) {
            ClassFacts type = classes.get(current);
            if (type == null) {
                return false;
            }
            if (superName.equals(type.superName()) || type.interfaces().contains(interfaceName)) {
                return true;
            }
            current = type.superName();
        }
        return false;
    }

    private List<MethodFacts> resolve(Call call) {
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

    private String externalOwner(String owner) {
        Set<String> seen = new HashSet<>();
        String current = owner;
        while (seen.add(current)) {
            ClassFacts type = classes.get(current);
            @Nullable String parent = type == null ? null : type.superName();
            if (type == null || parent == null) {
                return current;
            }
            current = parent;
        }
        return current;
    }
}
