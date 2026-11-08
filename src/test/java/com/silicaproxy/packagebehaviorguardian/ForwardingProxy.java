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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A minimal plain-HTTP forward proxy standing in for a corporate proxy: it records the first request
 * line of each connection ({@code GET http://host:port/path HTTP/1.1}) and relays the bytes as they
 * are to that host (HTTP/1.1 servers accept the absolute form).
 */
public final class ForwardingProxy implements AutoCloseable {

    private final ServerSocket server;
    private final List<String> requests = new CopyOnWriteArrayList<>();

    public ForwardingProxy() throws IOException {
        server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(this::accept);
    }

    public int port() {
        return server.getLocalPort();
    }

    /** First request line of each connection received. */
    public List<String> requests() {
        return requests;
    }

    private void accept() {
        while (!server.isClosed()) {
            try {
                Socket client = server.accept();
                Thread.ofVirtual().start(() -> relay(client));
            } catch (IOException e) {
                return; // closed
            }
        }
    }

    private void relay(Socket client) {
        try (client) {
            InputStream in = client.getInputStream();
            String requestLine = readLine(in);
            requests.add(requestLine);
            URI target = URI.create(requestLine.split(" ")[1]);
            int port = target.getPort() == -1 ? 80 : target.getPort();
            try (Socket upstream = new Socket(target.getHost(), port)) {
                OutputStream toUpstream = upstream.getOutputStream();
                toUpstream.write((requestLine + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                Thread pump = Thread.ofVirtual().start(() -> copy(in, toUpstream));
                copy(upstream.getInputStream(), client.getOutputStream());
                pump.interrupt();
            }
        } catch (IOException | RuntimeException e) {
            // connection reset by either side: the test sees the failure on its own end
        }
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1 && b != '\n') {
            if (b != '\r') {
                line.write(b);
            }
        }
        return line.toString(StandardCharsets.ISO_8859_1);
    }

    private static void copy(InputStream in, OutputStream out) {
        try {
            in.transferTo(out);
            out.flush();
        } catch (IOException e) {
            // one side closed: the relay ends
        }
    }

    @Override
    public void close() throws IOException {
        server.close();
    }
}
