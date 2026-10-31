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


package com.silicaproxy.packagebehaviorguardian.service.artifact;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class ArtifactDownloaderTest {

    private static final URI URL = URI.create("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz");
    private static final Duration TIMEOUT = Duration.ofMillis(300);

    private final ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor();

    @AfterEach
    void stopWatchdog() {
        watchdog.shutdownNow();
    }

    @Test
    @Timeout(10)
    void aBodyThatStopsSendingIsClosedAtTheDeadlineEvenIfItThenLooksComplete() {
        // Like the JDK HttpClient's body: once closed, a blocked read() returns -1, not an error.
        InputStream stalled = new StalledInputStream(false);

        assertThatThrownBy(() -> ArtifactDownloader.copyCapped(stalled, new ByteArrayOutputStream(), 1024, true, URL,
                watchdog, TIMEOUT))
                .isInstanceOf(IOException.class)
                .hasMessageStartingWith("Download not finished within")
                .hasMessageEndingWith(URL.toString());
    }

    @Test
    @Timeout(10)
    void aBodyThatFailsOnceClosedReportsTheTimeout() {
        InputStream stalled = new StalledInputStream(true);

        assertThatThrownBy(() -> ArtifactDownloader.copyCapped(stalled, new ByteArrayOutputStream(), 1024, false, URL,
                watchdog, TIMEOUT))
                .isInstanceOf(IOException.class)
                .hasMessageStartingWith("Download not finished within")
                .hasCauseInstanceOf(IOException.class);
    }

    @Test
    @Timeout(10)
    void aSilentServerDoesNotBlockTheJdkHttpClientBody() throws Exception {
        CountDownLatch released = new CountDownLatch(1);
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(200, 1_000_000);
            OutputStream body = exchange.getResponseBody();
            body.write(new byte[10]);
            body.flush();
            try {
                released.await(); // headers and a few bytes sent, then nothing
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.close();
        });
        server.start();
        try (HttpClient client = HttpClient.newHttpClient()) {
            URI url = URI.create("http://localhost:" + server.getAddress().getPort() + "/foo.tgz");
            InputStream body = client.send(HttpRequest.newBuilder(url).build(), HttpResponse.BodyHandlers.ofInputStream()).body();

            assertThatThrownBy(() -> ArtifactDownloader.copyCapped(body, new ByteArrayOutputStream(), 10_000_000, true, url,
                    watchdog, TIMEOUT))
                    .isInstanceOf(IOException.class)
                    .hasMessageStartingWith("Download not finished within");
        } finally {
            released.countDown();
            server.stop(0);
        }
    }

    @Test
    void aBodyReceivedInTimeIsCopiedAndLeftOpen() throws IOException, InterruptedException {
        TrackedInputStream in = new TrackedInputStream(new byte[100_000]);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        long size = ArtifactDownloader.copyCapped(in, out, 1024 * 1024, true, URL, watchdog, TIMEOUT);

        assertThat(size).isEqualTo(100_000);
        assertThat(out.size()).isEqualTo(100_000);
        // The deadline was cancelled: the watchdog does not close the stream afterwards.
        TimeUnit.MILLISECONDS.sleep(TIMEOUT.toMillis() * 2);
        assertThat(in.closed).isFalse();
    }

    /** Never returns any data: read() blocks until close(), then returns -1 or throws. */
    private static final class StalledInputStream extends InputStream {

        private final CountDownLatch closed = new CountDownLatch(1);
        private final boolean failOnceClosed;

        StalledInputStream(boolean failOnceClosed) {
            this.failOnceClosed = failOnceClosed;
        }

        @Override
        public int read() throws IOException {
            try {
                closed.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            }
            if (failOnceClosed) {
                throw new IOException("stream closed");
            }
            return -1;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            return read();
        }

        @Override
        public void close() {
            closed.countDown();
        }
    }

    private static final class TrackedInputStream extends ByteArrayInputStream {

        private volatile boolean closed;

        TrackedInputStream(byte[] content) {
            super(content);
        }

        @Override
        public void close() {
            closed = true;
        }
    }
}
