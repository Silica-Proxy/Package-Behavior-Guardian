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

import com.silicaproxy.packagebehaviorguardian.properties.PackageBehaviorGuardianProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Spring Boot entry point of packagebehaviorguardian. {@code @EnableScheduling} drives the two
 * pollers that make the service asynchronous: {@code AnalysisWorker} (claims queued analysis jobs)
 * and {@code CallbackDispatcher} (delivers verdicts back to SilicaProxy), plus {@code JobPurger}
 * (deletes old finished jobs and audit rows, on one instance at a time: see {@code SchedulerLockConfig}).
 */
@SpringBootApplication
@EnableConfigurationProperties(PackageBehaviorGuardianProperties.class)
@EnableScheduling
public class PackagebehaviorguardianApplication {

    public static void main(String[] args) {
        SpringApplication.run(PackagebehaviorguardianApplication.class, args);
    }
}
