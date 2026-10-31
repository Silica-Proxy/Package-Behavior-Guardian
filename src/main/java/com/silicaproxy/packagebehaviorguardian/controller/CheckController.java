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
import com.silicaproxy.packagebehaviorguardian.model.entity.CheckAudit;
import com.silicaproxy.packagebehaviorguardian.service.audit.AuditService;
import com.silicaproxy.packagebehaviorguardian.service.intake.CheckService;
import com.silicaproxy.packagebehaviorguardian.service.intake.UrlPolicy;
import com.silicaproxy.packagebehaviorguardian.service.statics.Texts;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * SilicaProxy's async contract: 202 while the version is analyzed, 200 when the verdict is already known.
 * Every check whose body is well formed is written to {@code check_audit}, refused ones included.
 */
@RestController
@RequestMapping("/v1")
@NullMarked
public class CheckController {

    private static final Logger LOG = LoggerFactory.getLogger(CheckController.class);

    private final CheckService checkService;
    private final AuditService auditService;

    public CheckController(CheckService checkService, AuditService auditService) {
        this.checkService = checkService;
        this.auditService = auditService;
    }

    @RequiresApiKey(Scope.CHECK)
    @PostMapping("/check")
    public ResponseEntity<CheckResponse> check(@Valid @RequestBody CheckRequest request, HttpServletRequest httpRequest) {
        Instant receivedAt = Instant.now();
        LOG.info("Check request: ecosystem={} package={} version={} url={} callbackHost={}",
                request.ecosystem(), LogSanitizer.sanitize(request.packageName()),
                LogSanitizer.sanitize(request.version()), LogSanitizer.sanitize(request.url()),
                callbackAuthority(request.callbackUrl()));
        CheckService.Result result;
        try {
            result = checkService.check(request);
        } catch (ResponseStatusException e) {
            CheckAudit.ResponseStatus status = e.getStatusCode().is4xxClientError()
                    ? CheckAudit.ResponseStatus.REJECTED : CheckAudit.ResponseStatus.ERROR;
            audit(request, httpRequest, receivedAt, e.getStatusCode().value(), status, e.getReason(), null);
            throw e;
        } catch (RuntimeException e) {
            audit(request, httpRequest, receivedAt, HttpStatus.INTERNAL_SERVER_ERROR.value(), CheckAudit.ResponseStatus.ERROR,
                    e.getClass().getSimpleName(), null);
            throw e;
        }
        CheckResponse response = result.response();
        LOG.info("Check {}/{}@{}: {}{}", request.ecosystem(), LogSanitizer.sanitize(request.packageName()),
                LogSanitizer.sanitize(request.version()), response.status(),
                response.verdict() == null ? "" : " " + response.verdict());
        HttpStatus status = response.verdict() == null ? HttpStatus.ACCEPTED : HttpStatus.OK;
        audit(request, httpRequest, receivedAt, status.value(),
                response.verdict() == null ? CheckAudit.ResponseStatus.PENDING : CheckAudit.ResponseStatus.DONE,
                response.reason(), result);
        return ResponseEntity.status(status).body(response);
    }

    // result: null when the check was refused or failed.
    private void audit(CheckRequest request, HttpServletRequest httpRequest, Instant receivedAt, int httpStatus,
            CheckAudit.ResponseStatus status, @Nullable String reason, CheckService.@Nullable Result result) {
        auditService.record(new CheckAudit(receivedAt, Duration.between(receivedAt, Instant.now()).toMillis(),
                request.ecosystem(), request.packageName(), result == null ? null : result.name(), request.version(),
                request.url(), callbackAuthority(request.callbackUrl()), httpRequest.getRemoteAddr(), httpStatus, status,
                result == null ? null : result.response().verdict(), reason == null ? null : Texts.clip(reason),
                result == null ? null : result.jobId()));
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
