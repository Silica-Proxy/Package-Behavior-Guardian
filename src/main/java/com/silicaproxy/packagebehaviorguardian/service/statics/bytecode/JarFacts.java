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

import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * What {@link JarInspector} extracted from a jar, and all {@link BytecodeRules} ever look at. Class
 * and owner names are JVM internal names ({@code java/lang/Runtime}).
 */
@NullMarked
public record JarFacts(
        List<ClassFacts> classes,
        Set<String> annotationProcessors,
        List<String> nativeLibraries,
        Set<String> pluginMojos) {

    public JarFacts {
        classes = List.copyOf(classes);
        annotationProcessors = Set.copyOf(annotationProcessors);
        nativeLibraries = List.copyOf(nativeLibraries);
        pluginMojos = Set.copyOf(pluginMojos);
    }

    public record ClassFacts(String name, @Nullable String superName, List<String> interfaces, List<MethodFacts> methods) {

        public ClassFacts {
            interfaces = List.copyOf(interfaces);
            methods = List.copyOf(methods);
        }
    }

    /** {@code usesXor}: the method contains an IXOR/LXOR instruction, a common hand-rolled string/byte decoder. */
    public record MethodFacts(String name, List<Call> calls, List<String> strings, boolean usesXor) {

        public MethodFacts {
            calls = List.copyOf(calls);
            strings = List.copyOf(strings);
        }

        public boolean calls(String owner, String method) {
            return calls.stream().anyMatch(call -> call.owner().equals(owner) && call.name().equals(method));
        }

        public boolean callsNamed(String method) {
            return calls.stream().anyMatch(call -> call.name().equals(method));
        }
    }

    public record Call(String owner, String name) {
    }
}
