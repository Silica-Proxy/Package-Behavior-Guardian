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
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import com.silicaproxy.packagebehaviorguardian.service.statics.HostileArtifactException;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Reads a jar without loading or executing anything: each {@code .class} is parsed by ASM, and only
 * the facts the rules need are kept (calls, string constants, XOR use per method). The jar is
 * hostile input: the entry count and each class's uncompressed size are capped (zip bombs), and a
 * malformed class blocks the package instead of being skipped -- an unreadable class is exactly
 * where something could hide.
 */
@NullMarked
public final class JarInspector {

    private static final String PROCESSOR_SERVICE = "META-INF/services/javax.annotation.processing.Processor";
    private static final String PROCESSOR_INTERFACE = "javax/annotation/processing/Processor";
    private static final String PLUGIN_DESCRIPTOR = "META-INF/maven/plugin.xml";
    private static final Pattern IMPLEMENTATION = Pattern.compile("<implementation>([^<]+)</implementation>");
    private static final List<String> NATIVE_SUFFIXES = List.of(".so", ".dll", ".dylib", ".jnilib");

    private final int maxEntries;
    private final long maxClassSizeBytes;

    public JarInspector(int maxEntries, long maxClassSizeBytes) {
        this.maxEntries = maxEntries;
        this.maxClassSizeBytes = maxClassSizeBytes;
    }

    public JarFacts inspect(Path jar) throws IOException {
        List<ClassFacts> classes = new ArrayList<>();
        Set<String> processors = new HashSet<>();
        List<String> nativeLibraries = new ArrayList<>();
        Set<String> mojos = new HashSet<>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            if (zip.size() > maxEntries) {
                throw new HostileArtifactException("Jar has " + zip.size() + " entries (limit " + maxEntries + ")", false);
            }
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                String lower = name.toLowerCase(Locale.ROOT);
                if (entry.isDirectory()) {
                    continue;
                }
                if (lower.endsWith(".class")) {
                    classes.add(readClass(read(zip, entry), processors));
                } else if (PROCESSOR_SERVICE.equals(name)) {
                    processors.addAll(serviceEntries(new String(read(zip, entry), StandardCharsets.UTF_8)));
                } else if (PLUGIN_DESCRIPTOR.equals(name)) {
                    mojos.addAll(pluginImplementations(new String(read(zip, entry), StandardCharsets.UTF_8)));
                } else if (NATIVE_SUFFIXES.stream().anyMatch(lower::endsWith)) {
                    nativeLibraries.add(name);
                }
            }
        }
        return new JarFacts(classes, processors, nativeLibraries, mojos);
    }

    private byte[] read(ZipFile zip, ZipEntry entry) throws IOException {
        try (InputStream in = zip.getInputStream(entry)) {
            byte[] bytes = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 8L, maxClassSizeBytes + 1));
            if (bytes.length > maxClassSizeBytes) {
                throw new HostileArtifactException("Jar entry exceeds " + maxClassSizeBytes + " bytes uncompressed", false);
            }
            return bytes;
        }
    }

    // One fully-qualified class name per line; '#' starts a comment.
    private static List<String> serviceEntries(String content) {
        List<String> names = new ArrayList<>();
        for (String line : content.split("\\R")) {
            int hash = line.indexOf('#');
            String name = (hash >= 0 ? line.substring(0, hash) : line).trim();
            if (!name.isEmpty()) {
                names.add(name.replace('.', '/'));
            }
        }
        return names;
    }

    // Mojo classes declared by a Maven plugin descriptor: they may extend an AbstractMojo subclass that
    // lives in another jar, which the class hierarchy alone cannot reveal. Read as text (no XML parser).
    private static List<String> pluginImplementations(String pluginXml) {
        List<String> names = new ArrayList<>();
        Matcher matcher = IMPLEMENTATION.matcher(pluginXml);
        while (matcher.find()) {
            names.add(matcher.group(1).trim().replace('.', '/'));
        }
        return names;
    }

    // A module-info's `provides javax.annotation.processing.Processor with ...` registers processors
    // as the services file does (javac reads it on the module path): they are added to `processors`.
    private static ClassFacts readClass(byte[] bytes, Set<String> processors) throws IOException {
        try {
            FactsVisitor visitor = new FactsVisitor(processors);
            new ClassReader(bytes).accept(visitor, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            return visitor.toFacts();
        } catch (RuntimeException e) {
            // ASM signals malformed class files with unchecked exceptions.
            throw new HostileArtifactException("Malformed class file in jar", e);
        }
    }

    private static final class FactsVisitor extends ClassVisitor {

        private String name = "";
        private @Nullable String superName;
        private List<String> interfaces = List.of();
        private final List<MethodCollector> methods = new ArrayList<>();
        private final Set<String> processors;

        FactsVisitor(Set<String> processors) {
            super(Opcodes.ASM9);
            this.processors = processors;
        }

        @Override
        public void visit(int version, int access, String className, @Nullable String signature,
                @Nullable String superClassName, String @Nullable [] interfaceNames) {
            this.name = className;
            this.superName = superClassName;
            this.interfaces = interfaceNames == null ? List.of() : List.of(interfaceNames);
        }

        @Override
        public ModuleVisitor visitModule(String moduleName, int access, @Nullable String version) {
            return new ModuleVisitor(Opcodes.ASM9) {
                @Override
                public void visitProvide(String service, String... providers) {
                    if (PROCESSOR_INTERFACE.equals(service)) {
                        processors.addAll(List.of(providers));
                    }
                }
            };
        }

        @Override
        public MethodVisitor visitMethod(int access, String methodName, String descriptor, @Nullable String signature,
                String @Nullable [] exceptions) {
            MethodCollector collector = new MethodCollector(methodName);
            methods.add(collector);
            return collector;
        }

        ClassFacts toFacts() {
            return new ClassFacts(name, superName, interfaces, methods.stream().map(MethodCollector::toFacts).toList());
        }
    }

    private static final class MethodCollector extends MethodVisitor {

        private final String name;
        private final List<Call> calls = new ArrayList<>();
        private final List<String> strings = new ArrayList<>();
        private boolean usesXor;

        MethodCollector(String name) {
            super(Opcodes.ASM9);
            this.name = name;
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String methodName, String descriptor, boolean isInterface) {
            calls.add(new Call(owner, methodName));
        }

        // Lambdas and method references compile to invokedynamic: the implementation method is a
        // bootstrap argument, so it is recorded as a call (otherwise `static { Runnable r = () -> exec(); }`
        // hides the exec). String-concatenation recipes (javac 9+) carry their constants there too.
        @Override
        public void visitInvokeDynamicInsn(String indyName, String descriptor, Handle bootstrap, Object... bootstrapArguments) {
            for (Object argument : bootstrapArguments) {
                if (argument instanceof Handle handle) {
                    calls.add(new Call(handle.getOwner(), handle.getName()));
                } else if (argument instanceof String string) {
                    strings.add(string);
                }
            }
        }

        @Override
        public void visitLdcInsn(Object value) {
            if (value instanceof String string) {
                strings.add(string);
            }
        }

        @Override
        public void visitInsn(int opcode) {
            if (opcode == Opcodes.IXOR || opcode == Opcodes.LXOR) {
                usesXor = true;
            }
        }

        MethodFacts toFacts() {
            return new MethodFacts(name, calls, strings, usesXor);
        }
    }
}
