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


package com.silicaproxy.packagebehaviorguardian.properties;

import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import java.nio.file.Path;
import java.util.List;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "packagebehaviorguardian")
@NullMarked
public record PackageBehaviorGuardianProperties(
    SecurityProperties security,
    IntakeProperties intake,
    ArtifactProperties artifact,
    RegistryProperties registries,
    QueueProperties queue,
    CallbackProperties callback,
    AnalysisProperties analysis,
    ScannerProperties scanners,
    @DefaultValue List<AllowlistEntry> allowlist
) {

    public record SecurityProperties(
        // Set to false only for local dev / tests: every endpoint becomes unauthenticated.
        @DefaultValue("true") boolean enabled,
        // Key of POST /v1/check, held by SilicaProxy and sent back on callbacks, which SilicaProxy
        // checks with the same key. Blank fails closed.
        @Nullable String apiKey,
        // Read-only key of GET /v1/reports: never the check key, which could forge callbacks.
        @Nullable String reportApiKey
    ) {}

    public record IntakeProperties(
        // Hosts ("host" or "host:port") an artifact or registry-metadata URL may point to, checked
        // on the request URL and on every redirect hop (anti-SSRF). Never an internal address.
        @DefaultValue List<String> allowedArtifactHosts,
        // Hosts ("host" or "host:port") a callbackUrl may point to: the SilicaProxy instances.
        // Empty refuses every check request (fail closed).
        @DefaultValue List<String> allowedCallbackHosts,
        // Accept plain http:// callback URLs: SilicaProxy on a private Docker network.
        @DefaultValue("false") boolean allowHttpCallbacks,
        // Accept plain http:// artifact URLs: local development and tests only (MITM otherwise).
        @DefaultValue("false") boolean allowHttpArtifacts
    ) {}

    public record ArtifactProperties(
        // Hard cap on one download (artifact or registry metadata); larger ones fail the job.
        @DefaultValue("200") long maxSizeMb,
        // A PyPI version can ship dozens of wheels; beyond this the job fails rather than
        // silently analyzing only part of the version.
        @DefaultValue("60") int maxFilesPerVersion,
        // Parent directory of the per-job scratch directories. Blank = java.io.tmpdir.
        @Nullable Path workDir
    ) {}

    public record RegistryProperties(
        // Used to list every file of a PyPI version.
        @DefaultValue("https://pypi.org") String pypiUrl
    ) {}

    public record QueueProperties(
        // Jobs analyzed in parallel by one instance.
        @DefaultValue("4") int concurrency,
        @DefaultValue("3") int maxAttempts,
        // Delay before retrying a failed job, multiplied by the attempt number.
        @DefaultValue("60") int retryBackoffSeconds,
        // analysisQueue health turns DEGRADED when the oldest PENDING job waited longer than this.
        // Keep it below SilicaProxy's pending-ttl-minutes for this service.
        @DefaultValue("30") int maxWaitMinutes
    ) {}

    public record CallbackProperties(
        @DefaultValue("3") int maxAttempts,
        // Delay before the 2nd attempt; doubled after each further failure.
        @DefaultValue("10") int initialBackoffSeconds
    ) {}

    public record AnalysisProperties(
        // Bump whenever rules or their severities change: results of an older rule set are
        // re-analyzed on the next check instead of being served from the cache.
        @DefaultValue("1") String ruleSetVersion,
        // Externally reachable base URL of this service, used to put a report link in the reason
        // sent to SilicaProxy. Blank = no link.
        @Nullable String publicBaseUrl
    ) {}

    public record ScannerProperties(
        ToolProperties guarddog,
        MalcontentProperties malcontent,
        BytecodeProperties bytecode
    ) {}

    public record ToolProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("guarddog") List<String> command,
        @DefaultValue("300") int timeoutSeconds
    ) {}

    public record MalcontentProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("mal") List<String> command,
        @DefaultValue("300") int timeoutSeconds,
        // Third-party rules come under heterogeneous licenses, some forbidding hosted use. Off
        // unless a deployment opts in knowingly; always passed explicitly (--third-party=false),
        // since malcontent enables them by default.
        @DefaultValue("false") boolean thirdPartyRules
    ) {}

    public record BytecodeProperties(
        @DefaultValue("true") boolean enabled,
        // JVM-006: groupId prefixes of known annotation-processor publishers.
        @DefaultValue List<String> knownAnnotationProcessorGroups
    ) {}

    /**
     * An expected behavior of one package (e.g. {@code esbuild} downloading its binary), set aside
     * from its verdict. Declared in configuration -- typically a versioned file reviewed by pull
     * request, imported with {@code spring.config.import} -- and applied on restart, also to versions
     * already analyzed. {@code ruleId} null = every rule; {@code detail}, when set, restricts the
     * entry to findings whose message or location contains it; {@code version}, when set, to that
     * exact version -- an entry without version also covers the future releases of the package, that
     * is, a compromised one.
     */
    public record AllowlistEntry(String ecosystem, String name, @Nullable String version, @Nullable String ruleId,
            @Nullable String detail, String reason) {

        public AllowlistEntry {
            if (detail != null && detail.isBlank()) {
                throw new IllegalArgumentException("allowlist entry for " + name + ": blank detail would match every finding");
            }
        }

        public boolean covers(String findingEcosystem, String findingName, String findingVersion, Finding finding) {
            if (!ecosystem.equals(findingEcosystem) || !name.equals(findingName)
                    || version != null && !version.equals(findingVersion)) {
                return false;
            }
            if (ruleId != null && !ruleId.equals(finding.ruleId())) {
                return false;
            }
            String location = finding.location();
            return detail == null || finding.message().contains(detail) || location != null && location.contains(detail);
        }
    }
}
