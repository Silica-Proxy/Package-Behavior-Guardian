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

import java.io.IOException;

/**
 * The analyzed package itself prevents its analysis: malformed class file, archive beyond the
 * zip-bomb limits, version too large, scanner flooding its output or running out of time on it.
 * Unlike an infrastructure failure (registry or database unreachable, tool missing), which is
 * retried and then gives up without a verdict, this ends in BLOCKED: otherwise an attacker would
 * only need a hostile archive to fall back on SilicaProxy's fail-open. {@code mayBeTransient}: the
 * cause could also be a passing overload (a scanner timeout), so it blocks only on the last attempt.
 */
public class HostileArtifactException extends IOException {

    private static final long serialVersionUID = 1L;

    private final boolean mayBeTransient;

    public HostileArtifactException(String message, boolean mayBeTransient) {
        super(message);
        this.mayBeTransient = mayBeTransient;
    }

    public HostileArtifactException(String message, Throwable cause) {
        super(message, cause);
        this.mayBeTransient = false;
    }

    public boolean mayBeTransient() {
        return mayBeTransient;
    }
}
