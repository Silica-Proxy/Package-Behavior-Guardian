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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Builds small jars of synthetic classes for the bytecode tests. */
public final class TestJars {

    private TestJars() {
    }

    /** A class whose static initializer runs {@code Runtime.getRuntime().exec("id")} (JVM-001). */
    public static byte[] classWithExecInStaticInitializer(String internalName) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
        MethodVisitor clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
        clinit.visitLdcInsn("id");
        clinit.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", false);
        clinit.visitInsn(Opcodes.POP);
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * A class whose static initializer runs {@code ((Runnable) () -> Runtime.getRuntime().exec("id")).run()}:
     * the exec sits in the synthetic method {@code lambda$static$0}, reached only through invokedynamic.
     */
    public static byte[] classWithLambdaInStaticInitializer(String internalName) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
        MethodVisitor clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        Handle metafactory = new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/LambdaMetafactory", "metafactory",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;"
                        + "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
                        + "Ljava/lang/invoke/CallSite;", false);
        clinit.visitInvokeDynamicInsn("run", "()Ljava/lang/Runnable;", metafactory, Type.getType("()V"),
                new Handle(Opcodes.H_INVOKESTATIC, internalName, "lambda$static$0", "()V", false), Type.getType("()V"));
        clinit.visitMethodInsn(Opcodes.INVOKEINTERFACE, "java/lang/Runnable", "run", "()V", true);
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();
        MethodVisitor lambda = writer.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                "lambda$static$0", "()V", null, null);
        lambda.visitCode();
        lambda.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
        lambda.visitLdcInsn("id");
        lambda.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", false);
        lambda.visitInsn(Opcodes.POP);
        lambda.visitInsn(Opcodes.RETURN);
        lambda.visitMaxs(0, 0);
        lambda.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /** A class whose static initializer only calls the static method {@code owner.name} (the payload lives elsewhere). */
    public static byte[] classWithStaticInitializerCalling(String internalName, String call) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
        MethodVisitor clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        int dot = call.lastIndexOf('.');
        clinit.visitMethodInsn(Opcodes.INVOKESTATIC, call.substring(0, dot), call.substring(dot + 1), "()V", false);
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /** A class with one method {@code run()} whose body calls each {@code owner.name} given, plus the given string constants. */
    public static byte[] classCalling(String internalName, String superName, String[] calls, String... strings) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, superName, null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        method.visitCode();
        for (String string : strings) {
            method.visitLdcInsn(string);
            method.visitInsn(Opcodes.POP);
        }
        for (String call : calls) {
            int dot = call.lastIndexOf('.');
            // Descriptors are irrelevant to the scanner and never verified: the class is only parsed.
            method.visitMethodInsn(Opcodes.INVOKESTATIC, call.substring(0, dot), call.substring(dot + 1), "()V", false);
        }
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /** Like {@link #classCalling}, for a class extending {@code java/lang/Object} and implementing {@code interfaceName}. */
    public static byte[] classImplementing(String internalName, String interfaceName, String[] calls) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", new String[] {interfaceName});
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        method.visitCode();
        for (String call : calls) {
            int dot = call.lastIndexOf('.');
            method.visitMethodInsn(Opcodes.INVOKESTATIC, call.substring(0, dot), call.substring(dot + 1), "()V", false);
        }
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /** A class extending {@code java/lang/Object} with one method per key, calling each {@code owner.name} of its value. */
    public static byte[] classWithMethods(String internalName, Map<String, String[]> methodCalls) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
        for (Map.Entry<String, String[]> entry : methodCalls.entrySet()) {
            MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, entry.getKey(), "()V", null, null);
            method.visitCode();
            for (String call : entry.getValue()) {
                int dot = call.lastIndexOf('.');
                method.visitMethodInsn(Opcodes.INVOKESTATIC, call.substring(0, dot), call.substring(dot + 1), "()V", false);
            }
            method.visitInsn(Opcodes.RETURN);
            method.visitMaxs(0, 0);
            method.visitEnd();
        }
        writer.visitEnd();
        return writer.toByteArray();
    }

    /** A class whose method {@code run()} returns {@code a ^ b} (a hashCode-like XOR, not a decoder). */
    public static byte[] classWithXor(String internalName) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "(II)I", null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ILOAD, 0);
        method.visitVarInsn(Opcodes.ILOAD, 1);
        method.visitInsn(Opcodes.IXOR);
        method.visitInsn(Opcodes.IRETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /** An interface declaring the abstract method {@code run()}. */
    public static byte[] interfaceWithRun(String internalName) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT, internalName, null,
                "java/lang/Object", null);
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "run", "()V", null, null).visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /** A {@code module-info.class} declaring {@code provides service with providers} (internal names). */
    public static byte[] moduleInfoProviding(String moduleName, String service, String... providers) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_MODULE, "module-info", null, null, null);
        ModuleVisitor module = writer.visitModule(moduleName, 0, null);
        module.visitRequire("java.base", Opcodes.ACC_MANDATED, null);
        module.visitProvide(service, providers);
        module.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * A class whose static initializer runs {@code System.getProperty(property) + suffix}, compiled as
     * javac 9+ does: {@code suffix} only exists in the invokedynamic string-concatenation recipe.
     */
    public static byte[] classWithConcatInStaticInitializer(String internalName, String property, String suffix) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
        MethodVisitor clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitLdcInsn(property);
        clinit.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "getProperty", "(Ljava/lang/String;)Ljava/lang/String;", false);
        Handle concatFactory = new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/StringConcatFactory", "makeConcatWithConstants",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;"
                        + "[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;", false);
        clinit.visitInvokeDynamicInsn("makeConcatWithConstants", "(Ljava/lang/String;)Ljava/lang/String;", concatFactory,
                "\u0001" + suffix);
        clinit.visitInsn(Opcodes.POP);
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    public static byte[] jar(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return bytes.toByteArray();
    }

    public static Map<String, byte[]> entries(Object... nameThenContent) {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        for (int i = 0; i < nameThenContent.length; i += 2) {
            Object content = nameThenContent[i + 1];
            entries.put((String) nameThenContent[i],
                    content instanceof String text ? text.getBytes(StandardCharsets.UTF_8) : (byte[]) content);
        }
        return entries;
    }
}
