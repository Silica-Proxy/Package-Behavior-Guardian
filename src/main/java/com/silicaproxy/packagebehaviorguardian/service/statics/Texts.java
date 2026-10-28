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

import java.util.regex.Pattern;
import org.jspecify.annotations.NullMarked;

/** Bounds and neutralises text extracted from analyzed packages before it is stored or shown. */
@NullMarked
public final class Texts {

    private static final Pattern CONTROL_CHARS = Pattern.compile("\\p{Cntrl}");
    private static final int MAX_LENGTH = 300;

    private Texts() {
    }

    public static String clip(String value) {
        String clean = CONTROL_CHARS.matcher(value).replaceAll(" ");
        return clean.length() <= MAX_LENGTH ? clean : clean.substring(0, MAX_LENGTH) + "…";
    }
}
