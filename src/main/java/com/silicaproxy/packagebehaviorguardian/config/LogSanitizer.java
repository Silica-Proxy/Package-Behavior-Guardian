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

package com.silicaproxy.packagebehaviorguardian.config;

import java.util.regex.Pattern;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * Neutralises user-controlled values before they are written to a log line. Control characters
 * (CR, LF, other) are replaced with an underscore to prevent log forging (FindSecBugs
 * CRLF_INJECTION_LOGS).
 */
@NullMarked
public final class LogSanitizer {

    private static final Pattern CONTROL_CHARS = Pattern.compile("\\p{Cntrl}");

    private LogSanitizer() {
    }

    public static @Nullable String sanitize(@Nullable String value) {
        return value == null ? null : CONTROL_CHARS.matcher(value).replaceAll("_");
    }
}
