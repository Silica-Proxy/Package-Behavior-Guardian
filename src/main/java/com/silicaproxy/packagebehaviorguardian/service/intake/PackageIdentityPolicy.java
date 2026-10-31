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


package com.silicaproxy.packagebehaviorguardian.service.intake;

import com.silicaproxy.packagebehaviorguardian.service.artifact.MavenLayout;
import com.silicaproxy.packagebehaviorguardian.service.artifact.NpmLayout;
import java.net.URI;
import java.util.Arrays;
import java.util.regex.Pattern;
import org.jspecify.annotations.NullMarked;

/**
 * Per-ecosystem check of (name, version, url) at intake. Names and versions end up in registry
 * URLs and in the path arithmetic of {@link MavenLayout} and {@link NpmLayout}, so they are held to
 * each registry's own charset, with no {@code ..} and no path separator. The URL must then be a
 * file of that very version (npm tarball, Maven file): the verdict is cached per (name, version),
 * whatever URL was analyzed. PyPI URLs are not bound, since a PyPI version is analyzed from the
 * file list of the JSON API, not from the requested URL.
 */
@NullMarked
public final class PackageIdentityPolicy {

    // Name rules of the npm registry (validate-npm-package-name), per part of "@scope/name"; upper case survives in legacy names.
    private static final Pattern NPM_PART = Pattern.compile("[A-Za-z0-9~-][A-Za-z0-9._~-]*");
    private static final int NPM_MAX_NAME_LENGTH = 214;
    // PEP 508 names: also starting and ending with a letter or digit, checked separately.
    private static final Pattern PYPI_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]*");
    private static final Pattern MAVEN_GROUP_SEGMENT = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern MAVEN_ARTIFACT_ID = Pattern.compile("[A-Za-z0-9_-][A-Za-z0-9._-]*");
    // Path and URL delimiters; "." and ".." are refused separately.
    private static final Pattern VERSION_FORBIDDEN = Pattern.compile("[/\\\\?#%]");

    private PackageIdentityPolicy() {
    }

    public static void require(String ecosystem, String name, String version, URI url) {
        if (".".equals(version) || "..".equals(version) || VERSION_FORBIDDEN.matcher(version).find()) {
            throw new IllegalArgumentException("Invalid version");
        }
        switch (ecosystem) {
            case "npm" -> npm(name, version, url);
            case "pypi" -> {
                if (!isPypiName(name)) {
                    throw new IllegalArgumentException("Invalid PyPI package name");
                }
            }
            case "maven" -> maven(name, version, url);
            default -> throw new IllegalArgumentException("Unsupported ecosystem " + ecosystem);
        }
    }

    private static void npm(String name, String version, URI url) {
        if (!isNpmName(name)) {
            throw new IllegalArgumentException("Invalid npm package name");
        }
        NpmLayout.requireTarball(url, name, version);
    }

    private static void maven(String name, String version, URI url) {
        MavenLayout.Coordinates coordinates = MavenLayout.Coordinates.parse(name);
        if (!isMavenGroupId(coordinates.groupId()) || !isMavenArtifactId(coordinates.artifactId())) {
            throw new IllegalArgumentException("Invalid Maven groupId:artifactId");
        }
        MavenLayout.requireFileOfVersion(url, coordinates, version);
    }

    private static boolean isNpmName(String name) {
        if (name.length() > NPM_MAX_NAME_LENGTH || name.contains("..")) {
            return false;
        }
        int slash = name.indexOf('/');
        if (slash < 0) {
            return NPM_PART.matcher(name).matches();
        }
        return name.charAt(0) == '@' && NPM_PART.matcher(name.substring(1, slash)).matches()
                && NPM_PART.matcher(name.substring(slash + 1)).matches();
    }

    private static boolean isPypiName(String name) {
        return PYPI_NAME.matcher(name).matches() && PYPI_NAME.matcher(name.substring(name.length() - 1)).matches();
    }

    private static boolean isMavenGroupId(String groupId) {
        return Arrays.stream(groupId.split("\\.", -1)).allMatch(segment -> MAVEN_GROUP_SEGMENT.matcher(segment).matches());
    }

    private static boolean isMavenArtifactId(String artifactId) {
        return MAVEN_ARTIFACT_ID.matcher(artifactId).matches() && !artifactId.contains("..");
    }
}
