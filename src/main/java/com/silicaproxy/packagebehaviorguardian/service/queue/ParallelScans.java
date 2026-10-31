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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.NullMarked;

/**
 * Runs the scans of one job, at most {@code parallelism} at a time, with the outcome of running them
 * one after the other: results in task order, and on failure the exception of the first failing task
 * in that order (a {@code HostileArtifactException} keeps its type), so a scanner failure still fails
 * the job exactly as before. Once a task fails, the later ones not started yet are skipped and, when
 * that failure is the one reported, the running ones are cancelled. Interrupting the calling thread
 * (shutdown, {@code queue.max-job-minutes}) cancels every task -- which kills their processes, see
 * {@code ProcessRunner} -- and waits for them before returning, so that nothing still writes to the
 * scratch directory once the job ends.
 */
@NullMarked
final class ParallelScans {

    private ParallelScans() {
    }

    @FunctionalInterface
    interface Scan<T> {
        T run() throws IOException;
    }

    static <T> List<T> runAll(List<Scan<T>> scans, int parallelism) throws IOException {
        if (parallelism <= 1 || scans.size() <= 1) {
            List<T> results = new ArrayList<>(scans.size());
            for (Scan<T> scan : scans) {
                results.add(scan.run());
            }
            return results;
        }
        Semaphore permits = new Semaphore(parallelism);
        AtomicInteger firstFailed = new AtomicInteger(Integer.MAX_VALUE);
        List<Future<T>> futures = new ArrayList<>(scans.size());
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            try {
                for (int i = 0; i < scans.size(); i++) {
                    int index = i;
                    Scan<T> scan = scans.get(i);
                    futures.add(executor.submit(() -> runOne(scan, index, permits, firstFailed)));
                }
                return collect(futures);
            } finally {
                // On success every future is done already; otherwise stop the rest before close() waits for them.
                futures.forEach(future -> future.cancel(true));
            }
        }
    }

    private static <T> T runOne(Scan<T> scan, int index, Semaphore permits, AtomicInteger firstFailed)
            throws IOException, InterruptedException {
        permits.acquire();
        try {
            if (index > firstFailed.get()) {
                throw new CancellationException("skipped: an earlier scan failed");
            }
            return scan.run();
        } catch (IOException | RuntimeException e) {
            firstFailed.accumulateAndGet(index, Math::min);
            throw e;
        } finally {
            permits.release();
        }
    }

    // In task order: when task i fails, every task before it has succeeded, so i is the failure the
    // sequential run would have thrown. A skipped or cancelled task always comes after a failure.
    private static <T> List<T> collect(List<Future<T>> futures) throws IOException {
        List<T> results = new ArrayList<>(futures.size());
        try {
            for (Future<T> future : futures) {
                results.add(future.get());
            }
            return results;
        } catch (ExecutionException e) {
            throw rethrow(e.getCause());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while scanning", e);
        }
    }

    private static IOException rethrow(Throwable cause) {
        if (cause instanceof IOException io) {
            return io;
        }
        if (cause instanceof RuntimeException runtime) {
            throw runtime;
        }
        if (cause instanceof Error error) {
            throw error;
        }
        return new IOException(cause);
    }
}
