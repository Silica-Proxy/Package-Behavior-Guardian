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

import java.nio.file.Path;
import java.util.List;
import org.jspecify.annotations.NullMarked;

/** Input of one static pass: every downloaded file of the version (several for PyPI), in the job's scratch directory. */
@NullMarked
public record ScanContext(String ecosystem, String name, String version, List<Path> artifacts, Path workDir) {

    public ScanContext {
        artifacts = List.copyOf(artifacts);
    }
}
