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


package com.silicaproxy.packagebehaviorguardian.model.entity;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * One suspicious behavior reported by a scanner. {@code ruleId} is stable across releases and is
 * what {@code behavior_allowlist.rule_id} refers to: {@code JVM-xxx} (bytecode), {@code BEH-07x}
 * (malcontent), {@code GDG-<guarddog rule>} (GuardDog). {@code location} is the file, class or
 * method concerned, when the scanner knows it. Every text field comes from hostile input (the
 * analyzed package) and is truncated by the scanners before it gets here.
 */
@NullMarked
public record Finding(String ruleId, Severity severity, String scanner, String message, @Nullable String location) {
}
