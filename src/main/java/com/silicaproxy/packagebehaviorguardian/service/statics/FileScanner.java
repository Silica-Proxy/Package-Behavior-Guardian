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

import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NullMarked;

/**
 * A scanner that looks at each file on its own, and whose findings depend only on that file's
 * content and on {@link #cacheKey(String)}: the analysis pipeline scans the files of a version in
 * parallel and reuses the findings of a file already scanned (see {@code ScanCache}). Findings name
 * the file by its local name ({@code artifact.getFileName()}), at the start of their location.
 */
@NullMarked
public interface FileScanner extends StaticScanner {

    /** Identifies what the findings depend on besides the file: the scanner and its result-changing settings. */
    String cacheKey(String ecosystem);

    /** Same failure contract as {@link StaticScanner#scan}: an incomplete scan throws. */
    List<Finding> scanFile(String ecosystem, Path artifact, Path workDir) throws IOException;

    @Override
    default List<Finding> scan(ScanContext context) throws IOException {
        List<Finding> findings = new ArrayList<>();
        for (Path artifact : context.artifacts()) {
            findings.addAll(scanFile(context.ecosystem(), artifact, context.workDir()));
        }
        return findings;
    }
}
