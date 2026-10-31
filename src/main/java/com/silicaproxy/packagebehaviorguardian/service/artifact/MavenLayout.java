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


package com.silicaproxy.packagebehaviorguardian.service.artifact;

import java.net.URI;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jspecify.annotations.NullMarked;

/**
 * Maven repository layout arithmetic. SilicaProxy sends the URL of whatever file the client asked
 * for (often the {@code .pom} first), while the analysis needs the main artifact of the version: it
 * is derived from that URL, so it stays on the same repository (and passes the same host check).
 */
@NullMarked
public final class MavenLayout {

    private static final Pattern PACKAGING = Pattern.compile("<packaging>\\s*([^<\\s]+)\\s*</packaging>");
    private static final Pattern COMMENT = Pattern.compile("(?s)<!--.*?-->");
    private static final Pattern FILE_SUFFIX = Pattern.compile("[.-][^/]+");

    private MavenLayout() {
    }

    /** {@code groupId:artifactId} split; rejects anything else. */
    public record Coordinates(String groupId, String artifactId) {

        public static Coordinates parse(String name) {
            int colon = name.indexOf(':');
            if (colon <= 0 || colon != name.lastIndexOf(':') || colon == name.length() - 1) {
                throw new IllegalArgumentException("Maven package name must be groupId:artifactId");
            }
            return new Coordinates(name.substring(0, colon), name.substring(colon + 1));
        }
    }

    /** {@code .../group/path/artifactId/version/artifactId-version.<extension>}, next to any file of that version. */
    public static URI file(URI anyFileOfVersion, Coordinates coordinates, String version, String extension) {
        String path = anyFileOfVersion.getRawPath();
        String versionDirectory = "/" + coordinates.groupId().replace('.', '/') + "/" + coordinates.artifactId() + "/" + version + "/";
        int index = path == null ? -1 : path.indexOf(versionDirectory);
        if (index < 0) {
            throw new IllegalArgumentException("Cannot locate " + versionDirectory + " in the artifact URL");
        }
        return anyFileOfVersion.resolve(path.substring(0, index) + versionDirectory
                + coordinates.artifactId() + "-" + version + "." + extension);
    }

    /**
     * {@code url} itself if it is a file of that version: its path ends with
     * {@code .../group/path/artifactId/version/artifactId-version<classifier and extension>}.
     */
    public static URI requireFileOfVersion(URI url, Coordinates coordinates, String version) {
        String path = url.getRawPath() == null ? "" : url.getRawPath();
        String fileStart = "/" + coordinates.groupId().replace('.', '/') + "/" + coordinates.artifactId() + "/" + version + "/"
                + coordinates.artifactId() + "-" + version;
        int index = path.lastIndexOf(fileStart);
        String rest = index < 0 ? "" : path.substring(index + fileStart.length());
        if (!FILE_SUFFIX.matcher(rest).matches()) {
            throw new IllegalArgumentException("The Maven URL is not a file of " + coordinates.groupId() + ":"
                    + coordinates.artifactId() + ":" + version);
        }
        return url;
    }

    /**
     * Extension of the main artifact declared by a POM's {@code <packaging>}; empty for {@code pom}
     * (BOMs, parents: no binary). Read as text, comments removed first, so that a commented-out
     * packaging cannot send the analysis to a file that does not exist.
     */
    public static Optional<String> mainArtifactExtension(String pom) {
        Matcher matcher = PACKAGING.matcher(COMMENT.matcher(pom).replaceAll(""));
        String packaging = matcher.find() ? matcher.group(1).toLowerCase(Locale.ROOT) : "jar";
        return switch (packaging) {
            case "pom" -> Optional.empty();
            case "war", "ear", "aar", "rar" -> Optional.of(packaging);
            default -> Optional.of("jar"); // jar, bundle, maven-plugin, ... all ship a .jar
        };
    }
}
