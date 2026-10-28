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


package com.silicaproxy.packagebehaviorguardian.service.statics;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Runs an external scanner (GuardDog, malcontent) with a timeout, a capped stdout and a minimal
 * environment: the child only sees PATH, HOME, LANG, a TMPDIR inside the job's scratch directory and
 * the {@code GUARDDOG_*} settings of the image (e.g. {@code GUARDDOG_TOP_PACKAGES_CACHE_LOCATION}) --
 * never this service's own secrets (database password, API key).
 */
@Component
@NullMarked
public class ProcessRunner {

    private static final int MAX_STDOUT_BYTES = 64 * 1024 * 1024;
    private static final int STDERR_TAIL_BYTES = 4000;
    private static final String PASSED_PREFIX = "GUARDDOG_";

    private final ObjectMapper objectMapper;

    public ProcessRunner(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public record ProcessResult(int exitCode, String stdout, String stderrTail) {
    }

    /**
     * Runs a tool that prints a JSON report. Exit codes are not trusted (they vary across tool
     * versions): the run fails only if stdout is not a JSON object.
     */
    public JsonNode runForJsonReport(List<String> command, Duration timeout, Path workDir) throws IOException {
        ProcessResult result = run(command, timeout, workDir);
        try {
            JsonNode report = objectMapper.readTree(result.stdout());
            if (report.isObject()) {
                return report;
            }
        } catch (JacksonException e) {
            // reported below with the exit code and stderr
        }
        throw new IOException(String.join(" ", command.subList(0, Math.min(2, command.size()))) + " exited with "
                + result.exitCode() + " without a JSON report: " + Texts.clip(result.stderrTail()));
    }

    public ProcessResult run(List<String> command, Duration timeout, Path workDir) throws IOException {
        return run(command, timeout, workDir, System.getenv());
    }

    // The parent environment is a parameter only so that tests can supply one.
    ProcessResult run(List<String> command, Duration timeout, Path workDir, Map<String, String> parentEnvironment)
            throws IOException {
        Path stderrFile = Files.createTempFile(workDir, "stderr-", ".log");
        ProcessBuilder builder = new ProcessBuilder(command)
                .directory(workDir.toFile())
                .redirectError(stderrFile.toFile())
                .redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        Map<String, String> environment = builder.environment();
        environment.clear();
        environment.put("PATH", parentEnvironment.getOrDefault("PATH", "/usr/local/bin:/usr/bin:/bin"));
        // Each job its own HOME: concurrent tools must not share caches or state.
        environment.put("HOME", workDir.toString());
        environment.put("LANG", "C.UTF-8");
        environment.put("TMPDIR", workDir.toString());
        parentEnvironment.forEach((name, value) -> {
            if (name.startsWith(PASSED_PREFIX) && !value.isBlank()) {
                environment.put(name, value);
            }
        });

        Process process = builder.start();
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        AtomicBoolean truncated = new AtomicBoolean();
        Thread reader = Thread.ofVirtual().start(() -> drain(process.getInputStream(), stdout, truncated));
        try {
            if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly().waitFor(5, TimeUnit.SECONDS);
                throw new HostileArtifactException(command.get(0) + " timed out after " + timeout.toSeconds() + "s", true);
            }
            reader.join(Duration.ofSeconds(10));
        } catch (InterruptedException e) {
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while running " + command.get(0), e);
        }
        if (truncated.get()) {
            throw new HostileArtifactException(command.get(0) + " produced more than " + MAX_STDOUT_BYTES / (1024 * 1024) + " MB of output", false);
        }
        return new ProcessResult(process.exitValue(), stdout.toString(StandardCharsets.UTF_8), tail(stderrFile));
    }

    private static void drain(InputStream in, ByteArrayOutputStream out, AtomicBoolean truncated) {
        byte[] buffer = new byte[64 * 1024];
        try (in) {
            int read;
            while ((read = in.read(buffer)) != -1) {
                if (out.size() + read > MAX_STDOUT_BYTES) {
                    truncated.set(true);
                    continue;
                }
                out.write(buffer, 0, read);
            }
        } catch (IOException e) {
            truncated.set(true);
        }
    }

    // Only the end of stderr is read (a hostile package can make a tool log gigabytes), and decoding
    // replaces invalid UTF-8 instead of failing: tools print raw bytes from the files they scan.
    private static String tail(Path stderrFile) throws IOException {
        try (SeekableByteChannel channel = Files.newByteChannel(stderrFile)) {
            long size = channel.size();
            ByteBuffer buffer = ByteBuffer.allocate((int) Math.min(size, STDERR_TAIL_BYTES));
            channel.position(size - buffer.capacity());
            while (buffer.hasRemaining() && channel.read(buffer) > 0) {
                // read until the tail is full
            }
            return new String(buffer.array(), 0, buffer.position(), StandardCharsets.UTF_8);
        } finally {
            Files.deleteIfExists(stderrFile);
        }
    }
}
