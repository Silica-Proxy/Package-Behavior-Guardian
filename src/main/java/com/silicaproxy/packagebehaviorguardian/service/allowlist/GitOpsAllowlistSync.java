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


package com.silicaproxy.packagebehaviorguardian.service.allowlist;

import com.silicaproxy.packagebehaviorguardian.config.LogSanitizer;
import com.silicaproxy.packagebehaviorguardian.config.Metrics;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AllowlistRepository;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties.GitOpsProperties;
import com.silicaproxy.packagebehaviorguardian.service.statics.Texts;
import io.micrometer.core.instrument.MeterRegistry;
import java.io.IOException;
import java.nio.file.Path;
import java.util.regex.Pattern;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * GitOps synchronization of the allowlist, on one instance at a time (ShedLock): fetch the repository,
 * read its files ({@link AllowlistFiles}), replace the {@code allowlist_entry} table. A failure keeps
 * the entries of the last success and is recorded for the {@code gitops} health and metrics. The other
 * instances pick the new entries up through {@link AllowlistStore}.
 */
@Service
@NullMarked
public class GitOpsAllowlistSync {

    private static final Logger LOG = LoggerFactory.getLogger(GitOpsAllowlistSync.class);
    // user:password@ in a URL that was configured with its credentials inline.
    private static final Pattern URL_CREDENTIALS = Pattern.compile("(?<=://)[^/@\\s]+@");

    private final GitOpsProperties gitops;
    private final GitWorkingCopy workingCopy;
    private final AllowlistRepository repository;
    private final AllowlistStore store;
    private final MeterRegistry meterRegistry;

    public GitOpsAllowlistSync(PackageBehaviorGuardianProperties properties, GitWorkingCopy workingCopy,
            AllowlistRepository repository, AllowlistStore store, MeterRegistry meterRegistry) {
        this.gitops = properties.gitops();
        this.workingCopy = workingCopy;
        this.repository = repository;
        this.store = store;
        this.meterRegistry = meterRegistry;
    }

    @Scheduled(initialDelayString = "${packagebehaviorguardian.gitops.initial-delay-ms:5000}",
            fixedDelayString = "#{${packagebehaviorguardian.gitops.sync-interval-minutes:10} * 60000}")
    @SchedulerLock(name = "pbg-gitops-allowlist", lockAtMostFor = "PT10M", lockAtLeastFor = "PT30S")
    public void scheduledSync() {
        if (gitops.enabled()) {
            sync();
        }
    }

    /** One synchronization, whatever the lock (tests, forced runs); true when it succeeded. */
    public boolean sync() {
        try {
            String revision = workingCopy.update(gitops);
            Path root = gitops.effectiveCloneDir();
            AllowlistFiles.Result result = AllowlistFiles.read(root, root.resolve(gitops.path()).normalize());
            result.skipped().forEach(reason -> LOG.warn("GitOps allowlist: entry skipped, {}", LogSanitizer.sanitize(reason)));
            long generation = repository.replace(result.entries(), revision, result.skipped().size());
            LOG.info("GitOps allowlist synchronized: {} entries ({} skipped) from commit {}, generation {}",
                    result.entries().size(), result.skipped().size(), revision, generation);
            count(Metrics.OUTCOME_SUCCESS);
            store.refresh();
            return true;
        } catch (IOException | RuntimeException e) {
            String error = Texts.clip(redact(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            LOG.error("GitOps allowlist synchronization failed, the entries in force are kept: {}", LogSanitizer.sanitize(error));
            count(Metrics.OUTCOME_FAILURE);
            try {
                repository.recordFailure(error);
            } catch (DataAccessException dbError) {
                LOG.warn("Could not record the GitOps allowlist failure: {}", dbError.getMessage());
            }
            return false;
        }
    }

    private void count(String outcome) {
        meterRegistry.counter(Metrics.GITOPS_SYNC_METRIC, Metrics.TAG_OUTCOME, outcome).increment();
    }

    static String redact(String message) {
        return URL_CREDENTIALS.matcher(message).replaceAll("***@");
    }
}
