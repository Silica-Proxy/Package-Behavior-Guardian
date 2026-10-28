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

/**
 * Which API key an endpoint accepts. Two keys, because they are held by different parties: the
 * check key also authenticates callbacks to SilicaProxy, so whoever only reads reports must not
 * hold it -- they could otherwise forge an ALLOWED callback.
 */
public enum Scope {
    /** {@code POST /v1/check} -- the key held by SilicaProxy, also sent on callbacks. */
    CHECK,
    /** {@code GET /v1/reports} -- read-only, for the people investigating a block. */
    REPORT
}
