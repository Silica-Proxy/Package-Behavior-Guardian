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

import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisJobRepository;
import com.silicaproxy.packagebehaviorguardian.dao.repository.AnalysisResultRepository;
import com.silicaproxy.packagebehaviorguardian.model.entity.AnalysisResult;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Stores a result and marks its job DONE atomically: the callback dispatcher only picks up DONE jobs,
 * so it never sees a DONE job without its result. A worker that lost its lease is rolled back.
 */
@Component
@NullMarked
public class JobCompletion {

    private final AnalysisJobRepository jobRepository;
    private final AnalysisResultRepository resultRepository;

    public JobCompletion(AnalysisJobRepository jobRepository, AnalysisResultRepository resultRepository) {
        this.jobRepository = jobRepository;
        this.resultRepository = resultRepository;
    }

    /** False (and nothing stored) when {@code workerId} no longer holds the job. */
    @Transactional
    public boolean complete(AnalysisResult result, String workerId) {
        if (!jobRepository.markDone(result.jobId(), workerId)) {
            return false;
        }
        resultRepository.upsert(result);
        return true;
    }
}
