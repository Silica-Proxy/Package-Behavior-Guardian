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
import org.jspecify.annotations.NullMarked;

/**
 * npm registry layout: the tarball of a version is {@code .../<name>/-/<basename>-<version>.tgz},
 * where the basename of {@code @scope/name} is {@code name}; some registries encode the scope
 * separator ({@code @scope%2fname}). The verdict is cached per (name, version), so the analyzed
 * tarball must be the one of that version, not whatever file the request pointed at.
 */
@NullMarked
public final class NpmLayout {

    private NpmLayout() {
    }

    /** {@code url} itself if it is the tarball of {@code name@version}; rejects anything else. */
    public static URI requireTarball(URI url, String name, String version) {
        String path = url.getRawPath() == null ? "" : url.getRawPath();
        int slash = name.indexOf('/');
        String basename = name.substring(slash + 1);
        String file = "/-/" + basename + "-" + version + ".tgz";
        String packagePath = path.endsWith(file) ? path.substring(0, path.length() - file.length()) : "";
        boolean plain = packagePath.endsWith("/" + name);
        boolean encodedScope = slash > 0 && packagePath.toLowerCase(Locale.ROOT)
                .endsWith(("/" + name.substring(0, slash) + "%2f" + basename).toLowerCase(Locale.ROOT));
        if (!plain && !encodedScope) {
            throw new IllegalArgumentException("The npm URL is not the tarball of " + name + "@" + version);
        }
        return url;
    }
}
