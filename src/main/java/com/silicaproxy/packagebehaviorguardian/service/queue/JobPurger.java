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
import com.silicaproxy.packagebehaviorguardian.dao.repository.AuditRepository;
import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import java.time.Duration;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Keeps the tables bounded. Deletes the DONE and FAILED jobs (with their results) neither updated nor
 * checked for {@code retention.days}, never one PENDING or RUNNING nor one with a callback still
 * waiting -- a purged version is simply analyzed again on its next check. Then deletes the audit rows
 * past {@code retention.analysis-audit-days} and {@code check-audit-days}, whatever became of their
 * job. Runs on one instance at a time (ShedLock); {@code SKIP LOCKED} still keeps the job purge out
 * of the way of checks and workers.
 */
@Component
@NullMarked
public class JobPurger {

    private static final Logger LOG = LoggerFactory.getLogger(JobPurger.class);
    private static final int BATCH_SIZE = 500;

    private final AnalysisJobRepository jobRepository;
    private final AuditRepository auditRepository;
    private final PackageBehaviorGuardianProperties.RetentionProperties retention;

    public JobPurger(AnalysisJobRepository jobRepository, AuditRepository auditRepository,
            PackageBehaviorGuardianProperties properties) {
        this.jobRepository = jobRepository;
        this.auditRepository = auditRepository;
        this.retention = properties.retention();
    }

    @Scheduled(fixedDelayString = "${packagebehaviorguardian.retention.purge-interval-ms:3600000}",
            initialDelayString = "${packagebehaviorguardian.retention.purge-interval-ms:3600000}")
    @SchedulerLock(name = "pbg-purge", lockAtLeastFor = "PT1M")
    public void purge() {
        if (retention.days() > 0) {
            try {
                int deleted = jobRepository.purgeFinished(Duration.ofDays(retention.days()), BATCH_SIZE);
                if (deleted > 0) {
                    LOG.info("Purged {} analysis jobs older than {} days", deleted, retention.days());
                }
            } catch (DataAccessException e) {
                LOG.warn("Could not purge old analysis jobs: {}", e.getMessage());
            }
        }
        if (retention.analysisAuditDays() > 0) {
            try {
                int deleted = auditRepository.purgeAnalyses(Duration.ofDays(retention.analysisAuditDays()), BATCH_SIZE);
                if (deleted > 0) {
                    LOG.info("Purged {} analysis audit rows older than {} days", deleted, retention.analysisAuditDays());
                }
            } catch (DataAccessException e) {
                LOG.warn("Could not purge the analysis audit: {}", e.getMessage());
            }
        }
        if (retention.checkAuditDays() > 0) {
            try {
                int deleted = auditRepository.purgeChecks(Duration.ofDays(retention.checkAuditDays()), BATCH_SIZE);
                if (deleted > 0) {
                    LOG.info("Purged {} check audit rows older than {} days", deleted, retention.checkAuditDays());
                }
            } catch (DataAccessException e) {
                LOG.warn("Could not purge the check audit: {}", e.getMessage());
            }
        }
    }
}
