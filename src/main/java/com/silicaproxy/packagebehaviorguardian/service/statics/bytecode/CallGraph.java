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
 * as {@code DefaultExecutor.execute}. A call on a jar class or interface also reaches the methods of
 * the same name overriding it in the jar's subtypes (class hierarchy analysis: the receiver's
 * run-time type is unknown, so {@code static { Plugin p = new EvilPlugin(); p.init(); }} reaches
 * {@code EvilPlugin.init}). Types outside the jar ({@code Runnable}, {@code Object}) are not
 * dispatched: every jar class would become reachable through {@code toString()}. The walk is
 * bounded in depth and size: hostile jars can build arbitrarily large graphs.
 *
 * <p>Queries are memoized for the life of the graph (one jar): a call's resolution, a method's
 * outgoing edges (resolved targets and the calls it makes leaving the jar) and each completed
 * {@link #reachFrom} result. Only completed walks are cached, keyed by their start: a reach is never
 * composed from the cached reach of a callee, since the depth and size bounds make what a callee
 * reaches depend on where the walk started, and a partial result taken mid-cycle would be wrong.
 * Not thread-safe: one graph serves one evaluation.
 */
@NullMarked
final class CallGraph {

    private static final int MAX_DEPTH = 6;
    private static final int MAX_METHODS = 2000;
    // Bound on the external calls held by cached reaches, so memoization cannot exhaust the heap.
    private static final int MAX_CACHED_CALLS = 500_000;

    /** A call leaving the jar, and the in-jar method that makes it. */
    record ExternalCall(Call call, String fromClass, String fromMethod) {
    }

    /** What a method can reach: calls leaving the jar, string constants, and whether any reached method XORs. */
    record Reach(List<ExternalCall> calls, Set<String> strings, boolean usesXor) {
    }

    /** A method's outgoing edges: calls leaving the jar, in call order, and the in-jar methods it calls, in call order. */
    private record Edges(List<ExternalCall> external, List<MethodFacts> targets) {
    }

    private final Map<String, ClassFacts> classes = new HashMap<>();
    private final Map<MethodFacts, String> ownerOf = new IdentityHashMap<>();
    private final Map<Call, List<MethodFacts>> resolved = new HashMap<>();
    private final Map<MethodFacts, Edges> edges = new IdentityHashMap<>();
    private final Map<MethodFacts, Reach> reaches = new IdentityHashMap<>();
    private int cachedCalls;
    private final Map<String, Set<String>> directSubtypes = new HashMap<>();

    CallGraph(JarFacts jar) {
        for (ClassFacts type : jar.classes()) {
            // A Multi-Release jar (META-INF/versions/N/...) or duplicate zip entries can hold several
            // classes of one name: their methods are merged, so a benign copy cannot hide another.
            classes.merge(type.name(), type, (first, second) -> new ClassFacts(first.name(), first.superName(), first.interfaces(),
                    java.util.stream.Stream.concat(first.methods().stream(), second.methods().stream()).toList()));
            type.methods().forEach(method -> ownerOf.put(method, type.name()));
            @Nullable String parent = type.superName();
            if (parent != null) {
                directSubtypes.computeIfAbsent(parent, key -> new HashSet<>()).add(type.name());
            }
            type.interfaces().forEach(name -> directSubtypes.computeIfAbsent(name, key -> new HashSet<>()).add(type.name()));
        }
    }

    /** Everything reachable from {@code start}, including its own calls and constants. */
    Reach reachFrom(MethodFacts start) {
        Reach cached = reaches.get(start);
        if (cached != null) {
            return cached;
        }
        Reach reach = walk(start);
        if (cachedCalls + reach.calls().size() <= MAX_CACHED_CALLS) {
            cachedCalls += reach.calls().size();
            reaches.put(start, reach);
        }
        return reach;
    }

    private Reach walk(MethodFacts start) {
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
                Edges out = edgesOf(method);
                result.addAll(out.external());
                for (MethodFacts target : out.targets()) {
                    if (visited.size() < MAX_METHODS && visited.add(target)) {
                        next.add(target);
                    }
                }
            }
            current = next;
        }
        return new Reach(List.copyOf(result), Collections.unmodifiableSet(strings), usesXor);
    }

    private Edges edgesOf(MethodFacts method) {
        Edges cached = edges.get(method);
        if (cached != null) {
            return cached;
        }
        List<ExternalCall> external = new ArrayList<>();
        List<MethodFacts> targets = new ArrayList<>();
        for (Call call : method.calls()) {
            List<MethodFacts> found = resolved.computeIfAbsent(call, this::resolve);
            if (found.isEmpty()) {
                external.add(new ExternalCall(new Call(externalOwner(call.owner()), call.name()),
                        ownerOf.getOrDefault(method, "?"), method.name()));
            }
            targets.addAll(found);
            targets.addAll(overriders(call));
        }
        Edges built = new Edges(List.copyOf(external), List.copyOf(targets));
        edges.put(method, built);
        return built;
    }

    /**
     * True if {@code className} extends {@code superName} or implements {@code interfaceName}, directly
     * or through jar classes and interfaces.
     */
    boolean inherits(String className, String superName, String interfaceName) {
        Set<String> seen = new HashSet<>();
        Deque<String> pending = new ArrayDeque<>(List.of(className));
        while (!pending.isEmpty()) {
            ClassFacts type = classes.get(pending.pop());
            if (type == null || !seen.add(type.name())) {
                continue;
            }
            if (superName.equals(type.superName()) || type.interfaces().contains(interfaceName)) {
                return true;
            }
            @Nullable String parent = type.superName();
            if (parent != null) {
                pending.add(parent);
            }
            pending.addAll(type.interfaces());
        }
        return false;
    }

    /** The methods named {@code methodName} declared by the jar class {@code className} (overloads merged). */
    List<MethodFacts> declared(String className, String methodName) {
        ClassFacts type = classes.get(className);
        return type == null ? List.of() : type.methods().stream().filter(method -> method.name().equals(methodName)).toList();
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

    // Constructors and static initializers are never dispatched: `new Base()` does not run the
    // subclasses' constructors.
    private List<MethodFacts> overriders(Call call) {
        if (call.name().startsWith("<") || !classes.containsKey(call.owner())) {
            return List.of();
        }
        List<MethodFacts> found = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Deque<String> pending = new ArrayDeque<>(directSubtypes.getOrDefault(call.owner(), Set.of()));
        while (!pending.isEmpty() && found.size() < MAX_METHODS) {
            String subtype = pending.pop();
            if (seen.add(subtype)) {
                found.addAll(declared(subtype, call.name()));
                pending.addAll(directSubtypes.getOrDefault(subtype, Set.of()));
            }
        }
        return found;
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
