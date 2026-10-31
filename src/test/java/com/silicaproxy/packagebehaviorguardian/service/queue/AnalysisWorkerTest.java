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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.silicaproxy.packagebehaviorguardian.TestProperties;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisJob;
import com.silicaproxy.packagebehaviorguardian.model.entity.JobStatus;
import com.silicaproxy.packagebehaviorguardian.service.verdict.VerdictPolicy;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AnalysisWorkerTest {

    private final AnalysisJobRepository jobRepository = mock(AnalysisJobRepository.class);
    private final AnalysisPipeline pipeline = mock(AnalysisPipeline.class);
    private final AnalysisWorker worker = new AnalysisWorker(jobRepository, pipeline, mock(VerdictPolicy.class),
            mock(JobCompletion.class), TestProperties.defaults(), mock(AnalysisMetrics.class));
    private final AnalysisJob job = new AnalysisJob(UUID.randomUUID(), "npm", "foo", "1.0.0",
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz", JobStatus.RUNNING, 1, null, Instant.now());

    @AfterEach
    void stopWorker() {
        worker.shutdown();
    }

    @Test
    @SuppressWarnings("unchecked")
    void aJobStuckPastMaxJobMinutesIsInterruptedAndItsLeaseNoLongerRenewed() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        when(jobRepository.claim(anyString(), anyInt(), any(Duration.class), anyInt())).thenReturn(List.of(job));
        when(pipeline.run(job)).thenAnswer(invocation -> {
            started.countDown();
            try {
                new CountDownLatch(1).await(); // a download that never ends, unless interrupted
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while fetching", e);
            }
            return null;
        });
        worker.poll();
        assertThat(started.await(5, TimeUnit.SECONDS)).isTrue();

        worker.renewLeases(Instant.now().plus(Duration.ofMinutes(29)));
        worker.renewLeases(Instant.now().plus(Duration.ofMinutes(31)));

        ArgumentCaptor<List<UUID>> renewed = ArgumentCaptor.forClass(List.class);
        verify(jobRepository, timeout(5000).times(2)).renewLeases(renewed.capture(), anyString(), any(Duration.class));
        assertThat(renewed.getAllValues()).containsExactly(List.of(job.id()), List.of());
        // The interrupted job fails with a clear reason, and is retried later (attempt 1 of 3).
        ArgumentCaptor<String> error = ArgumentCaptor.forClass(String.class);
        verify(jobRepository, timeout(5000)).markFailed(eq(job.id()), anyString(), error.capture(), anyBoolean(),
                any(Duration.class));
        assertThat(error.getValue()).startsWith("Analysis exceeded 30 min (queue.max-job-minutes): IOException");
    }
}
