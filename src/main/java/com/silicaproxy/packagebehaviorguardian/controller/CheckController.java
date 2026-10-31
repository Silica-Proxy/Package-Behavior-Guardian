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


package com.silicaproxy.packagebehaviorguardian.controller;

import com.silicaproxy.packagebehaviorguardian.config.LogSanitizer;
import com.silicaproxy.packagebehaviorguardian.config.RequiresApiKey;
import com.silicaproxy.packagebehaviorguardian.config.Scope;
import com.silicaproxy.packagebehaviorguardian.model.dto.CheckRequest;
import com.silicaproxy.packagebehaviorguardian.model.dto.CheckResponse;
import com.silicaproxy.packagebehaviorguardian.service.intake.CheckService;
import com.silicaproxy.packagebehaviorguardian.service.intake.UrlPolicy;
import jakarta.validation.Valid;
import java.net.URI;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** SilicaProxy's async contract: 202 while the version is analyzed, 200 when the verdict is already known. */
@RestController
@RequestMapping("/v1")
@NullMarked
public class CheckController {

    private static final Logger LOG = LoggerFactory.getLogger(CheckController.class);

    private final CheckService checkService;

    public CheckController(CheckService checkService) {
        this.checkService = checkService;
    }

    @RequiresApiKey(Scope.CHECK)
    @PostMapping("/check")
    public ResponseEntity<CheckResponse> check(@Valid @RequestBody CheckRequest request) {
        LOG.info("Check request: ecosystem={} package={} version={} url={} callbackHost={}",
                request.ecosystem(), LogSanitizer.sanitize(request.packageName()),
                LogSanitizer.sanitize(request.version()), LogSanitizer.sanitize(request.url()),
                callbackAuthority(request.callbackUrl()));
        CheckResponse response = checkService.check(request);
        LOG.info("Check {}/{}@{}: {}{}", request.ecosystem(), LogSanitizer.sanitize(request.packageName()),
                LogSanitizer.sanitize(request.version()), response.status(),
                response.verdict() == null ? "" : " " + response.verdict());
        HttpStatus status = response.verdict() == null ? HttpStatus.ACCEPTED : HttpStatus.OK;
        return ResponseEntity.status(status).body(response);
    }

    // The callback URL carries a secret token: only its host[:port] is logged.
    private static String callbackAuthority(String callbackUrl) {
        try {
            return UrlPolicy.authorityOf(URI.create(callbackUrl));
        } catch (IllegalArgumentException e) {
            return "invalid";
        }
    }
}
