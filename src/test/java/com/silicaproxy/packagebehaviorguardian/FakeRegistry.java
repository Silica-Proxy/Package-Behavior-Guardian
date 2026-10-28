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


package com.silicaproxy.packagebehaviorguardian;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-process HTTP server standing in for both a registry (static files registered with {@link #serve})
 * and SilicaProxy's callback endpoint (every POST under /callback/ is recorded).
 */
public final class FakeRegistry implements AutoCloseable {

    public record ReceivedCallback(String path, String authorization, String body) {
    }

    private final HttpServer server;
    private final Map<String, byte[]> files = new ConcurrentHashMap<>();
    private final List<ReceivedCallback> callbacks = new CopyOnWriteArrayList<>();

    public FakeRegistry() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            if ("POST".equals(exchange.getRequestMethod()) && path.startsWith("/callback/")) {
                callbacks.add(new ReceivedCallback(path, exchange.getRequestHeaders().getFirst("Authorization"),
                        new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
                exchange.sendResponseHeaders(path.endsWith("/gone") ? 404 : 200, -1);
                exchange.close();
                return;
            }
            byte[] content = files.get(path);
            if (content == null) {
                exchange.sendResponseHeaders(404, -1);
            } else {
                exchange.sendResponseHeaders(200, content.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(content);
                }
            }
            exchange.close();
        });
        server.start();
    }

    public void serve(String path, byte[] content) {
        files.put(path, content);
    }

    public String url(String path) {
        return "http://localhost:" + server.getAddress().getPort() + path;
    }

    public List<ReceivedCallback> callbacks() {
        return callbacks;
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
