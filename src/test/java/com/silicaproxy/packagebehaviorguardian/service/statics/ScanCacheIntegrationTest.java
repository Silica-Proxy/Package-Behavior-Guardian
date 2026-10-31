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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

import com.silicaproxy.packagebehaviorguardian.BaseIntegrationTest;
import com.silicaproxy.packagebehaviorguardian.TestProperties;
import com.silicaproxy.packagebehaviorguardian.dao.repository.ScanCacheRepository;
import com.silicaproxy.packagebehaviorguardian.model.entity.Finding;
import com.silicaproxy.packagebehaviorguardian.model.entity.Severity;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

class ScanCacheIntegrationTest extends BaseIntegrationTest {

    private static final Path WORK_DIR = Path.of("/tmp/pbg-job");

    @Autowired
    private ScanCacheRepository repository;

    @Autowired
    private JdbcClient jdbcClient;

    // The application purges every other rule set on its own schedule: entries expected to stay
    // cached use its rule set.
    @Autowired
    private PackageBehaviorGuardianProperties applicationProperties;

    private String current() {
        return applicationProperties.analysis().ruleSetVersion();
    }

    @Test
    void aHitDoesNotRunTheScannerAgainAndNamesTheFileOfTheCurrentJob() throws IOException {
        CountingScanner scanner = new CountingScanner();
        ScanCache cache = new ScanCache(repository, properties(current(), true));
        String sha256 = randomSha256();

        List<Finding> first = cache.scan(scanner, "pypi", WORK_DIR.resolve("0-shared-1.0-py3-none-any.whl"), sha256, WORK_DIR);
        // Same wheel published by another package (or another version): another local name.
        List<Finding> second = cache.scan(scanner, "pypi", WORK_DIR.resolve("3-other-2.0-py3-none-any.whl"), sha256, WORK_DIR);

        assertThat(scanner.calls).hasValue(1);
        assertThat(first).extracting(Finding::location)
                .containsExactly("0-shared-1.0-py3-none-any.whl", "0-shared-1.0-py3-none-any.whl: pkg/setup.py");
        assertThat(second).extracting(Finding::location)
                .containsExactly("3-other-2.0-py3-none-any.whl", "3-other-2.0-py3-none-any.whl: pkg/setup.py");
        assertThat(second).extracting(Finding::message)
                .containsExactly("rated high_risk", "runs code at install in 3-other-2.0-py3-none-any.whl");
        assertThat(second).extracting(Finding::ruleId, Finding::severity)
                .containsExactly(tuple("GDG-RISK", Severity.CRITICAL),
                        tuple("GDG-code-execution", Severity.HIGH));
    }

    @Test
    void theCacheIsKeyedByRuleSetAndScannerKey() throws IOException {
        CountingScanner scanner = new CountingScanner();
        String sha256 = randomSha256();
        Path artifact = WORK_DIR.resolve("0-pkg-1.0.tgz");

        new ScanCache(repository, properties(current(), true)).scan(scanner, "npm", artifact, sha256, WORK_DIR);
        new ScanCache(repository, properties(current() + "-next", true)).scan(scanner, "npm", artifact, sha256, WORK_DIR);
        new ScanCache(repository, properties(current(), true)).scan(scanner, "pypi", artifact, sha256, WORK_DIR);
        new ScanCache(repository, properties(current(), true)).scan(scanner, "npm", artifact, sha256, WORK_DIR);

        assertThat(scanner.calls).hasValue(3);
    }

    @Test
    void aFailedScanIsNeverCached() {
        CountingScanner scanner = new CountingScanner();
        scanner.failure = new HostileArtifactException("guarddog timed out after 300s", true);
        ScanCache cache = new ScanCache(repository, properties(current(), true));
        String sha256 = randomSha256();
        Path artifact = WORK_DIR.resolve("0-pkg-1.0.tgz");

        assertThatThrownBy(() -> cache.scan(scanner, "npm", artifact, sha256, WORK_DIR)).isSameAs(scanner.failure);
        assertThatThrownBy(() -> cache.scan(scanner, "npm", artifact, sha256, WORK_DIR)).isSameAs(scanner.failure);

        assertThat(scanner.calls).hasValue(2);
        assertThat(repository.find(sha256, "fake:npm", current())).isEmpty();
    }

    @Test
    void disabledCacheAlwaysScans() throws IOException {
        CountingScanner scanner = new CountingScanner();
        ScanCache cache = new ScanCache(repository, properties(current(), false));
        String sha256 = randomSha256();
        Path artifact = WORK_DIR.resolve("0-pkg-1.0.tgz");

        cache.scan(scanner, "npm", artifact, sha256, WORK_DIR);
        cache.scan(scanner, "npm", artifact, sha256, WORK_DIR);

        assertThat(scanner.calls).hasValue(2);
    }

    @Test
    void purgeRemovesOtherRuleSetsAndOldEntries() {
        String recent = randomSha256();
        String olderRuleSet = randomSha256();
        String old = randomSha256();
        repository.put(recent, "fake:npm", current(), List.of());
        repository.put(olderRuleSet, "fake:npm", current() + "-old", List.of());
        repository.put(old, "fake:npm", current(), List.of());
        jdbcClient.sql("UPDATE scan_cache SET created_at = now() - interval '31 days' WHERE sha256 = :sha256")
                .param("sha256", old).update();

        new ScanCache(repository, properties(current(), true)).purge();

        assertThat(repository.find(recent, "fake:npm", current())).isPresent();
        assertThat(repository.find(olderRuleSet, "fake:npm", current() + "-old")).isEmpty();
        assertThat(repository.find(old, "fake:npm", current())).isEmpty();
    }

    private static String randomSha256() {
        return (UUID.randomUUID().toString() + UUID.randomUUID()).replace("-", "");
    }

    private static PackageBehaviorGuardianProperties properties(String ruleSetVersion, boolean cacheEnabled) {
        PackageBehaviorGuardianProperties defaults = TestProperties.defaults();
        return new PackageBehaviorGuardianProperties(defaults.security(), defaults.intake(), defaults.artifact(),
                defaults.registries(), defaults.queue(), defaults.callback(), defaults.retention(),
                new PackageBehaviorGuardianProperties.AnalysisProperties(ruleSetVersion, null, 2, cacheEnabled, 30, 40, 20, 60),
                defaults.scanners(), defaults.allowlist());
    }

    /** Reports like the GuardDog parser: the file's local name at the start of each location. */
    private static final class CountingScanner implements FileScanner {

        private final AtomicInteger calls = new AtomicInteger();
        private IOException failure;

        @Override
        public String name() {
            return "fake";
        }

        @Override
        public boolean enabled() {
            return true;
        }

        @Override
        public boolean supports(String ecosystem) {
            return true;
        }

        @Override
        public String cacheKey(String ecosystem) {
            return name() + ":" + ecosystem;
        }

        @Override
        public List<Finding> scanFile(String ecosystem, Path artifact, Path workDir) throws IOException {
            calls.incrementAndGet();
            if (failure != null) {
                throw failure;
            }
            String file = String.valueOf(artifact.getFileName());
            return List.of(
                    new Finding("GDG-RISK", Severity.CRITICAL, "fake", "rated high_risk", file),
                    new Finding("GDG-code-execution", Severity.HIGH, "fake", "runs code at install in " + file, file + ": pkg/setup.py"));
        }
    }
}
