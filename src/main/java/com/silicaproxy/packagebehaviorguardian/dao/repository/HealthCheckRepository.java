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


package com.silicaproxy.packagebehaviorguardian.dao.repository;

import org.jspecify.annotations.NullMarked;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Plain database connectivity probe backing {@code MonitoringService}. */
@Repository
@NullMarked
public class HealthCheckRepository {

    private final JdbcClient jdbcClient;

    public HealthCheckRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    // Throws on any JDBC failure -- callers (MonitoringService) treat that as DOWN.
    public void isDatabaseReachable() {
        jdbcClient.sql("SELECT 1").query().singleRow();
    }
}
