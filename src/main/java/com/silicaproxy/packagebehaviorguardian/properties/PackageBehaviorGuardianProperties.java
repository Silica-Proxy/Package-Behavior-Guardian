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

import com.silicaproxy.packagebehaviorguardian.model.PackageNames;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import java.nio.file.Path;
import java.time.Duration;
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
    @DefaultValue RetentionProperties retention,
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
        @DefaultValue List<String> allowedCallbackHosts
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
        // Used to list every file of a PyPI version (JSON API /pypi/{name}/{version}/json).
        @DefaultValue("https://pypi.org") String pypiUrl,
        // Hosts ("host" or "host:port") serving the files that pypi-url lists, besides pypi-url's
        // own host. A PyPI check whose artifact URL is on another host is refused: the file list
        // of pypi-url would describe another index's package of the same name.
        @DefaultValue("files.pythonhosted.org") List<String> pypiFileHosts
    ) {}

    public record QueueProperties(
        // Jobs analyzed in parallel by one instance.
        @DefaultValue("4") int concurrency,
        @DefaultValue("3") int maxAttempts,
        // Delay before retrying a failed job, multiplied by the attempt number.
        @DefaultValue("60") int retryBackoffSeconds,
        // analysisQueue health turns DEGRADED when the oldest PENDING job waited longer than this.
        // Keep it below SilicaProxy's pending-ttl-minutes for this service.
        @DefaultValue("30") int maxWaitMinutes,
        // Beyond this, an analysis is presumed stuck: its thread is interrupted and its lease no
        // longer renewed, so the job is claimed again (or given up) once the lease expires.
        @DefaultValue("30") int maxJobMinutes
    ) {}

    public record CallbackProperties(
        // 11 attempts with the default backoff = retries over ~30 min (see application.yaml).
        @DefaultValue("11") int maxAttempts,
        // Delay before the 2nd attempt; doubled after each further failure, up to maxBackoffSeconds.
        @DefaultValue("10") int initialBackoffSeconds,
        @DefaultValue("300") int maxBackoffSeconds
    ) {

        public CallbackProperties {
            if (maxAttempts < 1 || initialBackoffSeconds < 1 || maxBackoffSeconds < initialBackoffSeconds) {
                throw new IllegalArgumentException("callback: max-attempts and initial-backoff-seconds must be >= 1,"
                        + " max-backoff-seconds >= initial-backoff-seconds");
            }
        }

        /** Delay before the next attempt of a callback that failed {@code attempts} times (>= 1). */
        public Duration retryDelay(int attempts) {
            long delay = (long) initialBackoffSeconds << Math.clamp(attempts - 1L, 0, 20);
            return Duration.ofSeconds(Math.min(delay, maxBackoffSeconds));
        }
    }

    public record RetentionProperties(
        // DONE and FAILED jobs neither updated nor checked for this many days are deleted with
        // their results (never a job PENDING or RUNNING, nor one with callbacks waiting). A later
        // check of the version analyzes it again. 0 = keep everything.
        @DefaultValue("90") int days
    ) {

        public RetentionProperties {
            if (days < 0) {
                throw new IllegalArgumentException("retention.days must be >= 0");
            }
        }
    }

    public record AnalysisProperties(
        // Bump whenever rules or their severities change: results of an older rule set are
        // re-analyzed on the next check instead of being served from the cache.
        @DefaultValue("1") String ruleSetVersion,
        // Externally reachable base URL of this service, used to put a report link in the reason
        // sent to SilicaProxy. Blank = no link.
        @Nullable String publicBaseUrl,
        // Files of one version scanned at the same time (each external scanner is one process per
        // file). An instance runs up to queue.concurrency × scan-parallelism scanner processes.
        @DefaultValue("2") int scanParallelism,
        // Reuse the findings of a file already scanned (same SHA-256, scanner and rule set) instead
        // of running the scanner again.
        @DefaultValue("true") boolean scanCacheEnabled,
        // Cache entries older than this are purged, so that a tool upgrade is eventually seen even
        // without a rule-set bump. Entries of another rule set are purged whatever their age.
        @DefaultValue("30") int scanCacheMaxAgeDays
    ) {}

    public record ScannerProperties(
        ToolProperties guarddog,
        MalcontentProperties malcontent,
        BytecodeProperties bytecode,
        IsolationProperties isolation
    ) {}

    /**
     * Each job's external scanners run under a uid of their own (see docker/scanner-exec.c): the job
     * gets one of {@code slots} ids from {@code first-gid} on, its scratch directory is handed to that
     * group (rwxr-x---) and its HOME to (rwxrwx---), and the launcher switches to uid = gid = the
     * group of its working directory. Blank {@code first-gid} = no isolation (development): the
     * scanners run as this service, in a private (rwx------) scratch directory. Set by the image,
     * together with the scanner-exec prefix of each {@code command}.
     */
    public record IsolationProperties(
        @Nullable Integer firstGid,
        @DefaultValue("64") int slots
    ) {

        public IsolationProperties {
            if (slots < 1) {
                throw new IllegalArgumentException("scanners.isolation.slots must be at least 1");
            }
        }
    }

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
     * already analyzed. {@code ruleId} null = every rule; {@code GDG-RISK} also covers the {@code
     * GDG-<threat rule>} findings GuardDog's rating is made of, which count since rule set 2;
     * {@code detail}, when set, restricts the entry to findings whose message or location contains
     * it; {@code version}, when set, to that exact version -- an entry without version also covers
     * the future releases of the package, that is, a compromised one. {@code name} is compared in
     * its canonical form ({@link PackageNames}): {@code Foo_Bar} also covers PyPI's {@code foo-bar}.
     */
    public record AllowlistEntry(String ecosystem, String name, @Nullable String version, @Nullable String ruleId,
            @Nullable String detail, String reason) {

        private static final String GUARDDOG_PACKAGE_RULE = "GDG-RISK";
        private static final String GUARDDOG_RULE_PREFIX = "GDG-";

        public AllowlistEntry {
            name = PackageNames.normalize(ecosystem, name);
            if (detail != null && detail.isBlank()) {
                throw new IllegalArgumentException("allowlist entry for " + name + ": blank detail would match every finding");
            }
        }

        public boolean covers(String findingEcosystem, String findingName, String findingVersion, Finding finding) {
            if (!ecosystem.equals(findingEcosystem) || !name.equals(PackageNames.normalize(findingEcosystem, findingName))
                    || version != null && !version.equals(findingVersion)) {
                return false;
            }
            if (ruleId != null && !ruleId.equals(finding.ruleId())
                    && !(GUARDDOG_PACKAGE_RULE.equals(ruleId) && finding.ruleId().startsWith(GUARDDOG_RULE_PREFIX))) {
                return false;
            }
            String location = finding.location();
            return detail == null || finding.message().contains(detail) || location != null && location.contains(detail);
        }
    }
}
