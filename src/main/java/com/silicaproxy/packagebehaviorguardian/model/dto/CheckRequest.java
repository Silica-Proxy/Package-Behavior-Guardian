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


package com.silicaproxy.packagebehaviorguardian.model.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NullMarked;

/**
 * Body of {@code POST /v1/check}, as sent by SilicaProxy for an async external validation service.
 * {@code ecosystem} arrives lowercase; a Maven {@code packageName} arrives as {@code
 * groupId:artifactId}. {@code url} is the artifact the client asked for; {@code callbackUrl} is
 * where the verdict must be POSTed. Both URLs are checked against host allowlists before use.
 * {@code packageName} and {@code version} reject control characters and whitespace (no registry
 * accepts them), which also keeps them from forging log lines. The per-ecosystem charsets, and the
 * binding of {@code url} to (name, version), are checked by {@code PackageIdentityPolicy}.
 */
@NullMarked
public record CheckRequest(
        @NotBlank @Size(max = 400) @Pattern(regexp = "[^\\p{Cntrl}\\s]+") String packageName,
        @NotBlank @Size(max = 200) @Pattern(regexp = "[^\\p{Cntrl}\\s]+") String version,
        @NotBlank @Pattern(regexp = "npm|pypi|maven") String ecosystem,
        @NotBlank @Size(max = 2000) String url,
        @NotBlank @Size(max = 2000) String callbackUrl) {
}
