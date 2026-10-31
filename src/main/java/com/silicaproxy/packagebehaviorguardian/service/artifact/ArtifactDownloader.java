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

import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import com.silicaproxy.packagebehaviorguardian.service.intake.UrlPolicy;
import com.silicaproxy.packagebehaviorguardian.service.statics.HostileArtifactException;
import jakarta.annotation.PreDestroy;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

/**
 * Size-capped, redirect-checked GET of registry artifacts and metadata. Redirects are followed by
 * hand, and every hop goes through {@link UrlPolicy} again (npm and PyPI legitimately redirect to
 * their CDN; an allowed host must not be able to bounce us to an internal address). Bodies are
 * streamed and aborted as soon as they exceed {@code artifact.max-size-mb} (20 MB for metadata,
 * which is held in memory) or take longer than {@link #TIMEOUT} -- the request timeout alone only
 * covers the response headers, not a server dripping the body byte by byte or sending nothing at
 * all. A watchdog closes the body when that deadline passes, so even a {@code read()} blocked on a
 * silent server returns.
 */
@Component
@NullMarked
public class ArtifactDownloader {

    private static final Set<Integer> REDIRECTS = Set.of(301, 302, 303, 307, 308);
    private static final int MAX_REDIRECTS = 5;
    private static final Duration TIMEOUT = Duration.ofMinutes(2);
    private static final long MAX_METADATA_BYTES = 20L * 1024 * 1024;

    private final HttpClient httpClient;
    private final UrlPolicy urlPolicy;
    private final long maxBytes;
    private final ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().name("artifact-download-watchdog").daemon().factory());

    public ArtifactDownloader(HttpClient httpClient, UrlPolicy urlPolicy, PackageBehaviorGuardianProperties properties) {
        this.httpClient = httpClient;
        this.urlPolicy = urlPolicy;
        this.maxBytes = properties.artifact().maxSizeMb() * 1024L * 1024L;
    }

    /** Downloads {@code url} to {@code target}; empty when the registry answers 404/410. */
    public Optional<DownloadedArtifact> download(URI url, Path target) throws IOException {
        Optional<InputStream> body = get(url);
        if (body.isEmpty()) {
            return Optional.empty();
        }
        MessageDigest digest = sha256();
        long size;
        try (InputStream in = body.get(); OutputStream out = new DigestOutputStream(Files.newOutputStream(target), digest)) {
            size = copyCapped(in, out, maxBytes, true, url, watchdog, TIMEOUT);
        }
        return Optional.of(new DownloadedArtifact(url, target, HexFormat.of().formatHex(digest.digest()), size));
    }

    /** Fetches a JSON registry document into memory. */
    public byte[] fetchMetadata(URI url) throws IOException {
        InputStream body = get(url).orElseThrow(() -> new IOException("Not found: " + url));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (body) {
            copyCapped(body, out, MAX_METADATA_BYTES, false, url, watchdog, TIMEOUT);
        }
        return out.toByteArray();
    }

    private Optional<InputStream> get(URI url) throws IOException {
        URI current = upgradeToHttps(urlPolicy.requireArtifactUrl(url.toString()));
        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            HttpRequest request = HttpRequest.newBuilder(current)
                    .timeout(TIMEOUT)
                    .header("User-Agent", "package-behavior-guardian")
                    .GET()
                    .build();
            HttpResponse<InputStream> response = send(request);
            int status = response.statusCode();
            if (status / 100 == 2) {
                return Optional.of(response.body());
            }
            response.body().close();
            if (REDIRECTS.contains(status)) {
                String location = response.headers().firstValue("Location")
                        .orElseThrow(() -> new IOException("Redirect without Location from " + url));
                current = upgradeToHttps(urlPolicy.requireArtifactUrl(current.resolve(location).toString()));
            } else if (status == 404 || status == 410) {
                return Optional.empty();
            } else {
                throw new IOException("HTTP " + status + " from " + current);
            }
        }
        throw new IOException("Too many redirects from " + url);
    }

    /**
     * Registries such as Maven Central refuse plain http with a 501, yet callers may hand us
     * {@code http://} URLs. An http URL on the default port is fetched over https; an explicit
     * port (local development, tests) is left alone.
     */
    static URI upgradeToHttps(URI uri) {
        if (!"http".equalsIgnoreCase(uri.getScheme()) || uri.getPort() != -1) {
            return uri;
        }
        return URI.create("https" + uri.toString().substring(4));
    }

    private HttpResponse<InputStream> send(HttpRequest request) throws IOException {
        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while fetching " + request.uri(), e);
        }
    }

    @PreDestroy
    public void shutdown() {
        watchdog.shutdownNow();
    }

    // Past the deadline the watchdog closes the body. Depending on the stream, the blocked read() then
    // throws or returns -1 (the JDK HttpClient's does): a body closed early is never taken as complete.
    static long copyCapped(InputStream in, OutputStream out, long limit, boolean artifact, URI url,
            ScheduledExecutorService watchdog, Duration timeout) throws IOException {
        AtomicBoolean expired = new AtomicBoolean();
        ScheduledFuture<?> deadline = watchdog.schedule(() -> {
            expired.set(true);
            closeQuietly(in);
        }, timeout.toNanos(), TimeUnit.NANOSECONDS);
        try {
            long total = copyCapped(in, out, limit, artifact, url);
            if (expired.get()) {
                throw timedOut(url, timeout, null);
            }
            return total;
        } catch (HostileArtifactException e) {
            throw e;
        } catch (IOException e) {
            throw expired.get() ? timedOut(url, timeout, e) : e;
        } finally {
            deadline.cancel(false);
        }
    }

    // An artifact over the limit is the package's doing (HostileArtifactException); registry metadata is not.
    private static long copyCapped(InputStream in, OutputStream out, long limit, boolean artifact, URI url) throws IOException {
        byte[] buffer = new byte[64 * 1024];
        long total = 0;
        int read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > limit) {
                String message = "Body larger than " + limit / (1024 * 1024) + " MB: " + url;
                throw artifact ? new HostileArtifactException(message, false) : new IOException(message);
            }
            out.write(buffer, 0, read);
        }
        return total;
    }

    private static IOException timedOut(URI url, Duration timeout, @Nullable IOException cause) {
        return new IOException("Download not finished within " + timeout.toSeconds() + " s: " + url, cause);
    }

    private static void closeQuietly(InputStream in) {
        try {
            in.close();
        } catch (IOException e) {
            // nothing to do: the watchdog only needs the blocked read() to return
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is mandatory in every JRE", e);
        }
    }
}
