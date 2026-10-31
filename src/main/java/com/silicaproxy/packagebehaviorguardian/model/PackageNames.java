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


package com.silicaproxy.packagebehaviorguardian.model;

import java.util.Locale;
import java.util.regex.Pattern;
import org.jspecify.annotations.NullMarked;

/**
 * The canonical form of a package name, under which a version is queued, reported and allowlisted:
 * two spellings the registry resolves to the same project must share one job (one verdict), and
 * two distinct projects must never.
 * <ul>
 *   <li>PyPI: PEP 503 -- lowercase, every run of {@code -}, {@code _} and {@code .} becomes one
 *       {@code -}. PyPI itself refuses a project whose normalized name collides with an existing
 *       one and serves {@code Foo_Bar} and {@code foo-bar} as the same project, so this never
 *       merges two packages.</li>
 *   <li>npm: unchanged. New names must be lowercase, but legacy mixed-case packages
 *       ({@code JSONStream}) are served under their exact spelling only -- the registry path is
 *       case-sensitive and {@code jsonstream} is another package (or a free name an attacker can
 *       register). Lowercasing would let one package's verdict answer for the other.</li>
 *   <li>Maven: unchanged. groupId and artifactId are case-sensitive path segments of the
 *       repository layout.</li>
 * </ul>
 * The name is validated as written in the request ({@code PackageIdentityPolicy}); since npm and
 * Maven names are kept verbatim, {@code NpmLayout} and {@code MavenLayout} keep matching the URL
 * against the very name stored in the job. PyPI URLs are not bound to the name (the version is
 * analyzed from the JSON API's file list).
 */
@NullMarked
public final class PackageNames {

    private static final Pattern PEP503_SEPARATORS = Pattern.compile("[-_.]+");

    private PackageNames() {
    }

    public static String normalize(String ecosystem, String name) {
        return "pypi".equals(ecosystem) ? normalizePypi(name) : name;
    }

    /** PEP 503: {@code re.sub(r"[-_.]+", "-", name).lower()}. */
    public static String normalizePypi(String name) {
        return PEP503_SEPARATORS.matcher(name).replaceAll("-").toLowerCase(Locale.ROOT);
    }
}
