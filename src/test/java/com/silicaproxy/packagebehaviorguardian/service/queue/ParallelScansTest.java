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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.silicaproxy.packagebehaviorguardian.service.statics.HostileArtifactException;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ParallelScansTest {

    @Test
    void resultsKeepTheTaskOrderAndAtMostParallelismRunAtOnce() throws IOException {
        AtomicInteger running = new AtomicInteger();
        AtomicInteger maxRunning = new AtomicInteger();
        List<ParallelScans.Scan<Integer>> scans = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            int value = i;
            scans.add(() -> {
                maxRunning.accumulateAndGet(running.incrementAndGet(), Math::max);
                sleep(12 - value); // later tasks finish first
                running.decrementAndGet();
                return value;
            });
        }

        List<Integer> results = ParallelScans.runAll(scans, 3);

        assertThat(results).containsExactly(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
        assertThat(maxRunning.get()).isBetween(2, 3);
    }

    @Test
    void theFirstFailureInTaskOrderIsThrownWithItsType() {
        HostileArtifactException hostile = new HostileArtifactException("mal produced more than 64 MB of output", false);
        List<ParallelScans.Scan<String>> scans = List.of(
                () -> "clean",
                () -> {
                    sleep(100); // fails after the later task: the sequential order still decides
                    throw hostile;
                },
                () -> {
                    throw new IOException("guarddog exited with 1 without a JSON report");
                });

        assertThatThrownBy(() -> ParallelScans.runAll(scans, 3)).isSameAs(hostile);
    }

    @Test
    void anIncompleteScanIsNeverAPartialResult() {
        List<ParallelScans.Scan<String>> scans = List.of(
                () -> {
                    throw new IOException("tool missing");
                },
                () -> "clean",
                () -> "clean");

        // whatever the parallelism, the job fails: no partial, clean-looking list of findings
        assertThatThrownBy(() -> ParallelScans.runAll(scans, 1)).hasMessage("tool missing");
        assertThatThrownBy(() -> ParallelScans.runAll(scans, 2)).hasMessage("tool missing");
    }

    @Test
    void interruptingTheJobCancelsTheRunningScansAndWaitsForThem() throws InterruptedException {
        CountDownLatch started = new CountDownLatch(2);
        AtomicInteger interrupted = new AtomicInteger();
        AtomicInteger stillRunning = new AtomicInteger();
        List<ParallelScans.Scan<String>> scans = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            scans.add(() -> {
                stillRunning.incrementAndGet();
                started.countDown();
                try {
                    Thread.sleep(Duration.ofMinutes(5));
                    return "never";
                } catch (InterruptedException e) {
                    interrupted.incrementAndGet();
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted while running mal", e);
                } finally {
                    stillRunning.decrementAndGet();
                }
            });
        }
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        AtomicBoolean interruptFlagKept = new AtomicBoolean();
        Thread job = Thread.ofVirtual().start(() -> {
            try {
                ParallelScans.runAll(scans, 2);
            } catch (IOException e) {
                thrown.set(e);
                interruptFlagKept.set(Thread.currentThread().isInterrupted());
            }
        });
        assertThat(started.await(10, TimeUnit.SECONDS)).isTrue();

        job.interrupt(); // what AnalysisWorker does to an overdue job (Future.cancel(true))
        assertThat(job.join(Duration.ofSeconds(10))).isTrue();

        assertThat(thrown.get()).isInstanceOf(IOException.class).isNotInstanceOf(HostileArtifactException.class);
        assertThat(interruptFlagKept).isTrue();
        assertThat(interrupted.get()).isEqualTo(2);
        assertThat(stillRunning.get()).isZero();
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
