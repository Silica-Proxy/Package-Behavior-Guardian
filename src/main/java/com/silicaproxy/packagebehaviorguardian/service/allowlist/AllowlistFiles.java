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


package com.silicaproxy.packagebehaviorguardian.service.allowlist;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AllowlistRepository.StoredEntry;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.AllowlistEntry;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.dataformat.yaml.YAMLMapper;

/**
 * Reads the allowlist files of a working copy: {@code <ecosystem>.yaml} (or {@code .yml}) for npm,
 * PyPI and Maven, the ecosystem coming from the file name.
 *
 * <pre>
 * allowlist:
 *   - name: esbuild
 *     version: 0.25.0        # optional
 *     rule-id: GDG-RISK      # optional
 *     detail: install hooks  # optional
 *     reason: downloads its platform binary at install, reviewed 2026-10-28
 * </pre>
 *
 * <p>A file that cannot be read as such (YAML syntax, oversized, a link leaving the directory) fails
 * the whole read: what its author meant is unknown, so the entries in force are kept. An invalid entry
 * (unknown key -- a misspelt {@code rule-id} would widen it to every rule --, missing name or reason,
 * blank detail) is skipped and counted: skipping one only ever narrows the allowlist. A missing file
 * means no entry for its ecosystem; a missing directory is an error (most likely a wrong {@code path}).
 */
@NullMarked
public final class AllowlistFiles {

    static final long MAX_FILE_BYTES = 1024 * 1024;
    private static final List<String> ECOSYSTEMS = List.of("npm", "pypi", "maven");

    private static final ObjectMapper YAML = YAMLMapper.builder()
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private AllowlistFiles() {
    }

    /** The entries read, and the number of invalid ones skipped (each one logged by the caller). */
    public record Result(List<StoredEntry> entries, List<String> skipped) {
        public Result {
            entries = List.copyOf(entries);
            skipped = List.copyOf(skipped);
        }
    }

    record FileEntry(@Nullable String name, @Nullable String version, @JsonProperty("rule-id") @Nullable String ruleId,
            @Nullable String detail, @Nullable String reason) { }

    /** Reads the files of {@code directory}, which must stay inside {@code root} (the working copy). */
    public static Result read(Path root, Path directory) throws IOException {
        Path realRoot = root.toRealPath();
        if (!Files.isDirectory(directory)) {
            throw new IOException("Allowlist directory not found in the repository: /" + root.relativize(directory));
        }
        Path realDirectory = directory.toRealPath();
        if (!realDirectory.startsWith(realRoot)) {
            throw new IOException("Allowlist directory leaves the repository");
        }
        List<StoredEntry> entries = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        for (String ecosystem : ECOSYSTEMS) {
            Path file = find(realDirectory, ecosystem);
            if (file != null) {
                readFile(realDirectory, file, ecosystem, entries, skipped);
            }
        }
        return new Result(entries, skipped);
    }

    private static @Nullable Path find(Path directory, String ecosystem) throws IOException {
        Path yaml = directory.resolve(ecosystem + ".yaml");
        Path yml = directory.resolve(ecosystem + ".yml");
        boolean hasYaml = Files.exists(yaml, LinkOption.NOFOLLOW_LINKS);
        boolean hasYml = Files.exists(yml, LinkOption.NOFOLLOW_LINKS);
        if (hasYaml && hasYml) {
            throw new IOException("Both " + ecosystem + ".yaml and " + ecosystem + ".yml exist: keep one");
        }
        return hasYaml ? yaml : hasYml ? yml : null;
    }

    private static void readFile(Path directory, Path file, String ecosystem, List<StoredEntry> entries,
            List<String> skipped) throws IOException {
        String fileName = String.valueOf(file.getFileName());
        int index = 0;
        for (JsonNode node : parse(directory, file, fileName)) {
            index++;
            try {
                FileEntry entry = YAML.treeToValue(node, FileEntry.class);
                entries.add(new StoredEntry(toEntry(ecosystem, entry), fileName));
            } catch (JacksonException e) {
                skipped.add(fileName + " entry #" + index + ": " + e.getOriginalMessage());
            } catch (IllegalArgumentException e) {
                skipped.add(fileName + " entry #" + index + ": " + e.getMessage());
            }
        }
    }

    // The entries of the file: none when it is empty.
    private static List<JsonNode> parse(Path directory, Path file, String fileName) throws IOException {
        JsonNode root = readYaml(directory, file, fileName);
        if (root == null || root.isMissingNode() || root.isNull()) {
            return List.of();
        }
        JsonNode list = root.get("allowlist");
        if (!root.isObject() || root.size() != 1 || list == null || !(list.isArray() || list.isNull())) {
            throw new IOException(fileName + " must hold a single 'allowlist' list");
        }
        List<JsonNode> nodes = new ArrayList<>();
        list.forEach(nodes::add);
        return nodes;
    }

    private static @Nullable JsonNode readYaml(Path directory, Path file, String fileName) throws IOException {
        // A link (Git stores symbolic links) could point anywhere on this host.
        Path real = file.toRealPath();
        if (!real.startsWith(directory) || !Files.isRegularFile(real)) {
            throw new IOException(fileName + " is not a regular file of the allowlist directory");
        }
        if (Files.size(real) > MAX_FILE_BYTES) {
            throw new IOException(fileName + " is larger than " + MAX_FILE_BYTES + " bytes");
        }
        try {
            return YAML.readTree(Files.readAllBytes(real));
        } catch (JacksonException e) {
            throw new IOException(fileName + " is not valid YAML: " + e.getOriginalMessage(), e);
        }
    }

    private static AllowlistEntry toEntry(String ecosystem, FileEntry entry) {
        String name = entry.name();
        String reason = entry.reason();
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("'name' is required");
        }
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("'reason' is required (" + name + ")");
        }
        return new AllowlistEntry(ecosystem, name.strip(), optional(entry.version()), optional(entry.ruleId()),
                entry.detail(), reason.strip());
    }

    // A blank version or rule-id would otherwise never match (version) or be refused nowhere (rule-id).
    private static @Nullable String optional(@Nullable String value) {
        if (value != null && value.isBlank()) {
            throw new IllegalArgumentException("a blank value is not allowed: remove the key instead");
        }
        return value == null ? null : value.strip();
    }
}
