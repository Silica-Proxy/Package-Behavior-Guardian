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


package com.silicaproxy.packagebehaviorguardian.service.queue;

import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import java.time.Duration;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Keeps the tables bounded: deletes the DONE and FAILED jobs (with their results) neither updated
 * nor checked for {@code retention.days}, never one PENDING or RUNNING nor one with a callback still
 * waiting. A purged version is simply analyzed again on its next check. Runs on every instance;
 * {@code SKIP LOCKED} keeps them out of each other's way.
 */
@Component
@NullMarked
public class JobPurger {

    private static final Logger LOG = LoggerFactory.getLogger(JobPurger.class);
    private static final int BATCH_SIZE = 500;

    private final AnalysisJobRepository jobRepository;
    private final int retentionDays;

    public JobPurger(AnalysisJobRepository jobRepository, PackageBehaviorGuardianProperties properties) {
        this.jobRepository = jobRepository;
        this.retentionDays = properties.retention().days();
    }

    @Scheduled(fixedDelayString = "${packagebehaviorguardian.retention.purge-interval-ms:3600000}",
            initialDelayString = "${packagebehaviorguardian.retention.purge-interval-ms:3600000}")
    public void purge() {
        if (retentionDays == 0) {
            return;
        }
        try {
            int deleted = jobRepository.purgeFinished(Duration.ofDays(retentionDays), BATCH_SIZE);
            if (deleted > 0) {
                LOG.info("Purged {} analysis jobs older than {} days", deleted, retentionDays);
            }
        } catch (DataAccessException e) {
            LOG.warn("Could not purge old analysis jobs: {}", e.getMessage());
        }
    }
}
