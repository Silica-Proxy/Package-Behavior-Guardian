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
import java.util.List;
import org.jspecify.annotations.NullMarked;

/**
 * One tool of the static pass: it reads the artifacts, never executes them. A scanner that
 * cannot finish (tool missing, timeout, unreadable output) throws, and the job is retried then
 * failed -- it never turns a failure into an empty, ALLOWED-looking result.
 */
@NullMarked
public interface StaticScanner {

    String name();

    boolean enabled();

    boolean supports(String ecosystem);

    List<Finding> scan(ScanContext context) throws IOException;
}
