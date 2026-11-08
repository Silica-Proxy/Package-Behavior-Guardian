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

import com.silicaproxy.packagebehaviorguardian.config.CorporateProxy;
import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URISyntaxException;
import java.net.URL;
import org.eclipse.jgit.transport.http.HttpConnection;
import org.eclipse.jgit.transport.http.HttpConnectionFactory;
import org.eclipse.jgit.transport.http.JDKHttpConnectionFactory;
import org.jspecify.annotations.NullMarked;

/** JGit's JDK connections, each routed by {@code route} whatever proxy JGit itself picked. */
@NullMarked
final class RoutedGitConnections implements HttpConnectionFactory {

    private final HttpConnectionFactory delegate = new JDKHttpConnectionFactory();
    private final ProxySelector route;

    RoutedGitConnections(ProxySelector route) {
        this.route = route;
    }

    @Override
    public HttpConnection create(URL url) throws IOException {
        return delegate.create(url, proxyFor(url));
    }

    @Override
    public HttpConnection create(URL url, Proxy ignored) throws IOException {
        return delegate.create(url, proxyFor(url));
    }

    private Proxy proxyFor(URL url) throws IOException {
        try {
            return CorporateProxy.proxyFor(route, url.toURI());
        } catch (URISyntaxException e) {
            throw new IOException("Invalid Git URL: " + e.getMessage(), e);
        }
    }
}
