# Package Behavior Guardian — Malicious Package Detection Service

[![SilicaProxy Logo](https://raw.githubusercontent.com/Silica-Proxy/Silica-Proxy/main/logo.png)](https://github.com/Silica-Proxy/Silica-Proxy)

Package Behavior Guardian analyzes **what a package does** (npm, PyPI, Maven), to catch a malicious release in the minutes after it is first requested, before any public advisory lists it. Its main target is the **compromised legitimate package**: a well-known name whose new version suddenly steals credentials or runs a payload at install or load time.

It is called by [SilicaProxy](https://github.com/Silica-Proxy/Silica-Proxy) as an **asynchronous External Validation Service**, and fits next to [Package-Name-Guardian](https://github.com/Silica-Proxy/Package-Name-Guardian) (typosquatting, synchronous).

> **Status:** only the **static pass** is implemented: nothing from the analyzed package is ever executed. A sandboxed dynamic pass (OpenSSF Package Analysis on gVisor) comes later. Run it in SilicaProxy with `blocking: false` (observation) until false positives have been measured.

---

## How it works

```
SilicaProxy ──POST /v1/check──► API ──► analysis_job (PostgreSQL queue, SKIP LOCKED)
     ▲            202 / 200                     │
     │                                          ▼
     │                               worker: download the whole version
     │                               static scanners ──► findings ──► verdict
     │                                          │
     └──── POST callbackUrl {verdict, reason} ◄─┘   (CallbackDispatcher)
```

1. **Intake.** `url` and `callbackUrl` are checked against host allowlists (anti-SSRF), the version is queued once per `(ecosystem, name, version)` — PyPI names in their PEP 503 form (`Foo_Bar` and `foo-bar` share one job, one report, one allowlist entry); npm and Maven names are kept as written, since their registry paths are case-sensitive (`JSONStream` is not `jsonstream`) — and the callback URL is recorded. A version already analyzed under the current rule set answers `200` with its verdict, and the verdict is also delivered to the callback (SilicaProxy's async client ignores the response body).
2. **Whole version.** SilicaProxy caches one verdict per version, whatever file was asked first, so the analysis covers the version, not just that file: the npm tarball; **every** PyPI file (sdist and all wheels, yanked ones included: pip still installs them when the version is pinned); for Maven, the main artifact given by the POM's `<packaging>` (`jar`, `war`, `aar`…; none for `pom`), plus the requested file when it is another archive (a classifier jar). A file that should exist but does not fails the job instead of passing.
3. **Static scanners** (each one can be disabled):

   | Scanner | Ecosystems | What it does | Finding IDs |
   |---|---|---|---|
   | [GuardDog](https://github.com/DataDog/guarddog) 3.x (Datadog, Apache-2.0) | npm, PyPI | YARA threat/capability rules on code and metadata, correlated into a package rating | `GDG-RISK`, `GDG-<rule>` |
   | [malcontent](https://github.com/chainguard-dev/malcontent) (Chainguard, Apache-2.0) | all | Capability YARA rules, including binaries | `BEH-071`, `BEH-072`, `BEH-073` |
   | Bytecode (ASM, in-process) | Maven | Calls in static initializers, annotation processors, Mojos… | `JVM-001` … `JVM-007` |

4. **Verdict** (two verdicts only): findings covered by the allowlist are set aside, then one `CRITICAL` blocks; otherwise `HIGH` (40) and `MEDIUM` (20) add up, each rule once, and a score ≥ 60 blocks with *"manual review required"*. The reason carries a report link.
5. **Callback** `POST {callbackUrl}` with `Authorization: Bearer <api-key>`, retried with exponential backoff. `404`/`410` means SilicaProxy no longer waits for that token (already resolved, or expired) and the callback is dropped.

**Process cost.** GuardDog and malcontent run once per file: the files of a version are scanned `analysis.scan-parallelism` at a time (default 2; one at a time under scanner isolation, where all the scanners of a job share its uid), and the findings of each (file SHA-256, scanner, rule set) are kept in the `scan_cache` table, so a file already scanned — shared by several versions or packages, or analyzed again after a requeue — is not scanned again. Only complete scans are cached; the file's name in the findings is replaced on reuse. Bumping `rule-set-version` (or `scan-cache-max-age-days` passing) makes the files be scanned again. Interrupting a job (shutdown, `max-job-minutes`) kills all its scanner processes.

A package that **prevents its own analysis** — malformed class file, archive beyond the zip-bomb limits, file over `max-size-mb`, version over 1 GB or 60 files, scanner flooding its output, scanner timing out on the last attempt — is **BLOCKED by `PBG-001`** (otherwise a hostile archive would be enough to fall back on SilicaProxy's fail-open). An **infrastructure** failure (registry or database unreachable, tool missing) is retried, then marked `FAILED` without a verdict: SilicaProxy's pending entry times out and its `fail-open` policy applies; the next check of that version queues it again.

### Rules

| ID | Detection | Severity |
|---|---|---|
| JVM-001 | `Runtime.exec` / `ProcessBuilder.start` in a static initializer or an annotation processor (MEDIUM in a Maven Mojo) | CRITICAL |
| JVM-002 | `defineClass` / `URLClassLoader` in a method that XORs, or with Base64 decoding reachable from it (or reaching it) through the call graph | CRITICAL |
| JVM-003 | Network call (`URL.openConnection`, `Socket`, `HttpClient`, `InetAddress.getByName`) in a static initializer or an annotation processor (MEDIUM in a Mojo) | HIGH |
| JVM-004 | Reads `user.home` and refers to a credential path (`.ssh`, `.aws`, `.m2/settings.xml`, `.npmrc`…) | HIGH |
| JVM-005 | Embedded native library **and** `System.load`/`loadLibrary` | MEDIUM |
| JVM-006 | Annotation processor declared by a publisher outside `known-annotation-processor-groups` | MEDIUM |
| JVM-007 | Reflective call (`Method.invoke`, `MethodHandle`, `Lookup.find*`) reachable from a static initializer or a processor, with the process-execution names in clear (MEDIUM in a Mojo) — HIGH when the names are decoded at run time (Base64 / XOR) | CRITICAL |
| PBG-001 | The package prevents its own analysis (see above) | CRITICAL |
| BEH-071 / 072 / 073 | malcontent: a file rated CRITICAL / HIGH / MEDIUM | CRITICAL / HIGH / MEDIUM |
| GDG-RISK | GuardDog package rating `high_risk` / `suspicious` | CRITICAL / HIGH |
| GDG-&lt;rule&gt; | One GuardDog risk, at its GuardDog severity (high/critical, medium, low); at least MEDIUM in a package rated `suspicious` or `high_risk`. An allowlist entry for `GDG-RISK` also covers them | HIGH / MEDIUM / LOW |

JVM-001, 003 and 007 follow calls through the jar's own classes, lambdas included (`static { Helper.run(); }` with the payload in `Helper`); a call on a jar interface or superclass also reaches its overrides in the jar. A Mojo is any class extending `AbstractMojo` or declared in `META-INF/maven/plugin.xml`; an annotation processor is declared in `META-INF/services` or in `module-info` (`provides javax.annotation.processing.Processor`), or extends `AbstractProcessor` / implements `Processor`, possibly through other jar classes. In a Maven Mojo they are only MEDIUM: plugins legitimately spawn processes and download tools (exec-maven-plugin, frontend-maven-plugin). For JVM-003, `URL.openStream`/`openConnection` counts only when the URL is built (`new URL`, `URI.toURL`) by the reading class or by a method the reading method calls: a URL from `getResource()` reads the jar itself.

**Not covered: reflection and method handles.** A call made through `Method.invoke`, `Constructor.newInstance` or a `MethodHandle` is not followed: its target is a run-time value, so the call graph stops there. JVM-007 only reports two shapes of it (process-execution names in clear, names decoded by Base64 / XOR); names assembled otherwise (run-time concatenation, char arrays, another encoding, a resource file), and a jar class reached reflectively (`Class.forName("com.x.Payload").getMethod("run").invoke(null)`), are not seen. Dispatch on JDK types (`Runnable.run`, `Object.toString`) is not resolved to the jar's implementations either, except for lambdas and method references.

---

## API

| Endpoint | Key (`Authorization: Bearer …`) | Purpose |
|---|---|---|
| `POST /v1/check` | `security.api-key`, held by SilicaProxy and also sent on callbacks | SilicaProxy async contract: `202 {"status":"PENDING"}` or `200 {"status":"DONE","verdict":…,"reason":…}` |
| `GET /v1/reports?ecosystem=&name=&version=` | `security.report-api-key`, read-only — never the check key, which could forge callbacks | Full report: files and SHA-256, findings, allowlisted findings, last error. The verdict is given only for a `DONE` job of the current rule set: none while a requeued job is `PENDING` or `RUNNING`, and status `OUTDATED` for a result of an older rule set |
| `GET /api/monitoring/health`, `/actuator/health`, `/actuator/prometheus` | — | Health (`database`, `analysisQueue`) and metrics |

```json
POST /v1/check
{ "packageName": "lodash", "version": "4.17.22", "ecosystem": "npm",
  "url": "https://registry.npmjs.org/lodash/-/lodash-4.17.22.tgz",
  "callbackUrl": "https://silica.internal/external-validation/callback/0b6c…" }

→ callback: { "verdict": "BLOCKED",
              "reason": "BLOCKED by BEH-071 (malcontent rates this file CRITICAL: …) — report: https://pbg.internal/v1/reports?ecosystem=npm&name=lodash&version=4.17.22" }
```

**Allowlist.** Expected behaviors live in configuration, in a versioned file reviewed by pull request (`docker/allowlist.yaml`, imported with `SPRING_CONFIG_IMPORT`):

```yaml
packagebehaviorguardian:
  allowlist:
    - ecosystem: npm
      name: esbuild
      version: 0.25.0            # optional: without it, the entry also covers future (possibly compromised) releases
      rule-id: GDG-RISK          # optional: every rule when absent; GDG-RISK also covers the GDG-<rule> risks
      detail: install hooks      # optional: only findings whose message or location contain it
      reason: downloads its platform binary at install, reviewed 2026-10-28
```

Entries apply on restart, also to versions already analyzed (verdicts are recomputed from stored findings). They cannot lift a BLOCKED verdict SilicaProxy already stored permanently: that takes a SilicaProxy policy.

---

## SilicaProxy configuration

```yaml
silicaproxy:
  external-validation:
    callback-base-url: "https://silica.internal"
    services:
      package-behavior-guardian:
        url: "https://pbg.internal/v1/check"
        api-key: "${PBG_API_KEY}"            # = packagebehaviorguardian.security.api-key
        mode: async
        fail-open: true
        blocking: false                      # observation first, then true
        cache-ttl-minutes: 20160             # 14 days > the longest quarantine
        pending-ttl-minutes: 120             # > queue.max-wait-minutes
```

SilicaProxy checks callbacks with the same per-service `api-key` it sends, so `security.api-key` here must equal it. The phase-1 SilicaProxy changes (`ecosystems` filter per service, `trigger-during-quarantine`) are not required, but they are what makes the analysis run during the quarantine.

---

## Configuration

All under `packagebehaviorguardian.*` (see `src/main/resources/application.yaml` for every default).

| Property | Env variable | Default | Description |
|---|---|---|---|
| `security.api-key` | `PACKAGEBEHAVIORGUARDIAN_API_KEY` | — | Key of `POST /v1/check`, also sent on callbacks; blank = refused |
| `security.report-api-key` | `PACKAGEBEHAVIORGUARDIAN_REPORT_API_KEY` | — | Read-only key of `GET /v1/reports`; blank = refused |
| `intake.allow-http-callbacks` / `allow-http-artifacts` | `…_INTAKE_ALLOWHTTPCALLBACKS` | `false` / `false` | Plain http for callbacks (SilicaProxy on a private network) / for artifacts (development only) |
| `intake.allowed-artifact-hosts` | — | npm, PyPI, Maven Central hosts | Exact `host` or `host:port` (`host:*` = any port, for development) |
| `intake.allowed-callback-hosts` | `PACKAGEBEHAVIORGUARDIAN_CALLBACK_HOSTS` | *(empty)* | SilicaProxy hosts; **empty refuses every check** |
| `queue.concurrency` / `max-attempts` / `max-wait-minutes` / `max-job-minutes` | `PACKAGEBEHAVIORGUARDIAN_QUEUE_CONCURRENCY` | `4` / `3` / `30` / `30` | Jobs per instance, attempts before FAILED, health threshold, duration after which a job is interrupted and its lease abandoned |
| `callback.max-attempts` / `initial-backoff-seconds` / `max-backoff-seconds` | — | `11` / `10` / `300` | Callback retries: delay doubled after each failure up to the cap, ~30 min in all, then dropped |
| `retention.days` / `purge-interval-ms` | `PACKAGEBEHAVIORGUARDIAN_RETENTION_DAYS` | `90` / `3600000` | DONE/FAILED jobs neither updated nor checked for that long are purged with their results (never PENDING/RUNNING jobs or jobs with callbacks waiting); a purged version is re-analyzed on its next check; `0` keeps everything |
| `registries.pypi-url` / `pypi-file-hosts` | — | `https://pypi.org` / `files.pythonhosted.org` | JSON API listing a PyPI version's files, and the hosts serving them; a PyPI artifact URL on any other host is refused (the list would describe another index's package) |
| `analysis.rule-set-version` | — | `2` | Bump when rules change: older results are re-analyzed on the next check |
| `analysis.scan-parallelism` | `PACKAGEBEHAVIORGUARDIAN_SCAN_PARALLELISM` | `2` | Files of one version scanned at the same time (forced to 1 under scanner isolation, i.e. in the image); an instance runs up to `queue.concurrency` × this many scanner processes |
| `analysis.scan-cache-enabled` / `scan-cache-max-age-days` | — | `true` / `30` | Reuse per-file scanner findings by (SHA-256, scanner, rule set); older entries and other rule sets are purged |
| `analysis.public-base-url` | `PACKAGEBEHAVIORGUARDIAN_PUBLIC_BASE_URL` | — | Base of the report link in reasons |
| `scanners.guarddog.*` | — | enabled | `command`, `timeout-seconds` |
| `scanners.malcontent.*` | — | enabled | `command`, `timeout-seconds`, `third-party-rules` (**false**) |
| `scanners.bytecode.*` | — | enabled | `known-annotation-processor-groups` |
| `scanners.isolation.first-gid` / `slots` | `…_SCANNERS_ISOLATION_FIRSTGID` / `…_SLOTS` | blank / `64` | Per-job scanner uids (set by the image, see [Scanner isolation](#scanner-isolation)); blank = the scanners run as the service |
| `artifact.max-size-mb` / `max-files-per-version` / `work-dir` | `PACKAGEBEHAVIORGUARDIAN_WORK_DIR` | `200` / `60` / tmp | Download limits and scratch directory |
| `allowlist` | — | `[]` | Expected behaviors (see [API](#api)) |

---

## Deployment

One image, which holds the jar and the tools of the static pass. It uses SilicaProxy's building blocks, in their glibc variants since malcontent only ships as a glibc binary: a jlink'ed Liberica 25 JRE on Alpaquita Linux (`stream-glibc`), Python 3.14 from Alpaquita, GuardDog 3.2.0 in a virtualenv (pygit2 and yara-python compiled against Alpaquita's libgit2 and OpenSSL), malcontent 1.28.0.

```bash
docker build -t silicaproxy/packagebehaviorguardian .
```

Every replica is identical: it answers SilicaProxy, analyzes queued jobs and sends callbacks. Replicas are stateless: jobs and callbacks are claimed with `SELECT … FOR UPDATE SKIP LOCKED`, and a job whose replica died is taken over when its lease expires, so replicas can be added or removed at any time. Capacity is replicas × `queue.concurrency` analyses at a time, each scanning up to `analysis.scan-parallelism` files at once.

`docker/compose.yaml` deploys PostgreSQL and 2 replicas, joined to SilicaProxy's Docker network (`cp docker/.env.example docker/.env` first; the SilicaProxy-side settings are listed at the end of that file). SilicaProxy calls `http://packagebehaviorguardian:8101/v1/check`.

```bash
docker compose up -d                                     # PostgreSQL + PBG_REPLICAS replicas (2)
docker compose up -d --scale packagebehaviorguardian=4   # more analysis capacity
```

Keep `PBG_REPLICAS × PBG_DB_POOL_SIZE` below `PBG_POSTGRES_MAX_CONNECTIONS`, and `PBG_CONCURRENCY` at about half the CPUs of a container. Run end to end with two replicas (2026-10-28): work is shared between them and each callback is delivered exactly once.

The static pass never executes package code, but it parses hostile archives: give the containers no access to the internal network beyond PostgreSQL, the registries and SilicaProxy, and no secrets other than their own.

### Scanner isolation

GuardDog and malcontent parse untrusted archives, so in the image they never run as the service: each job in flight gets its own unprivileged user, with no capability, an empty environment and access to nothing but its own artifacts. A scanner exploit cannot reach the service's secrets (database password, API keys), its files, or another job, and every process it leaves behind is killed when the job ends. The uid switch is done by a small launcher with only the two capabilities it needs (`docker/scanner-exec.c`, whose header explains the design).

Two things to know when deploying:

- keep `no-new-privileges` **off** on the container (the launcher sets it on the scanners itself); with it on, every scan fails (`FAILED`, never `ALLOWED`);
- a replica runs at most 64 jobs at once (`SCANNER_SLOTS` build argument); more jobs wait for a slot.

Outside the image (`./gradlew bootRun`, tests) the scanners run as the service, in a private scratch directory with the same scrubbed environment.

### Licenses

`./gradlew check` runs `checkLicense`: every runtime dependency must carry a license listed in `config/allowed-licenses.json`. GuardDog's dependency `pygit2` (GPL-2.0 with linking exception) is in the image, but only runs inside GuardDog's own process, never linked to the Java code. malcontent is always run with `--third-party=false`: **malcontent enables third-party rules by default**, some of which forbid hosted use. See `NOTICE`.

The SBOM is not generated by the Gradle build (the CycloneDX plugin's dependencies are refused by the dependency proxy used for development); generate it from the image in CI (e.g. Syft).

---

## Development

```bash
docker compose up -d            # PostgreSQL on localhost:5434
./gradlew bootRun               # port 8101
./gradlew check                 # tests (Testcontainers), Checkstyle, PMD, SpotBugs, licenses
```

Tests do not need GuardDog or malcontent: their parsers are tested on fixtures, and `ExternalScannersIntegrationTest` replaces both tools with shell scripts.

### Pinned dependencies

- **Gradle**: dependency verification is on (`gradle/verification-metadata.xml`, SHA-256 of every jar, POM and plugin). After adding or bumping a dependency or plugin, regenerate it and review the diff: `./gradlew --write-verification-metadata sha256 check bootJar`. The two Spring plugin marker POMs differ between the Gradle Plugin Portal and Maven Central: both checksums are trusted (`also-trust`).
- **Docker base images**: pinned by digest, the tag kept for readability (`image:tag@sha256:…`); Dependabot bumps the digests. By hand: `docker buildx imagetools inspect <image:tag>`. malcontent (`cgr.dev`, only `latest` is free) is pinned by digest in the `MALCONTENT_IMAGE` argument and updated deliberately.
- **GuardDog**: installed with `pip install --require-hashes --no-deps` from `docker/guarddog-requirements.txt` and `docker/guarddog-build-requirements.txt` (pip-compile locks with hashes); the command that regenerates them is in `docker/guarddog-build-requirements.in`.

### Known limits and points to check

- **Checked on real packages** (2026-10-28, Docker image: Python 3.14.10, GuardDog 3.2.0, pygit2 1.18.2, yara-python 4.5.4, malcontent 1.28.0): left-pad, esbuild, requests (sdist + wheel), guava, lombok, exec-maven-plugin, sqlite-jdbc, zstd-jni, jackson-bom are all ALLOWED (esbuild and requests score 40: GuardDog rates them *suspicious* for their install hooks / test fixtures; exec-maven-plugin and the JNI jars score 15). A synthetic npm package that evals base64, serializes `process.env` and runs a detached `curl | sh` is rated `high_risk` (9.4/10) by GuardDog: BLOCKED. The JSON formats of both tools match the parsers. Re-check them whenever the pinned versions change.
- GuardDog loads its typosquatting rule (and refreshes its popular-packages cache, over the network when stale) even for local scans: the image points `GUARDDOG_TOP_PACKAGES_CACHE_LOCATION` at a writable copy.
- **Scoring is not calibrated yet**: on npm/PyPI the only non-CRITICAL signal is GuardDog's `suspicious` rating (40), so the 60 threshold is never reached there without a CRITICAL. Whether malcontent's HIGH behaviors should count too is to be decided on the observation-phase data (false-positive risk: esbuild and requests already score 40).
- Only the **static** pass: an obfuscated payload that defeats the YARA rules and the bytecode rules is not seen until the dynamic pass.
- Bytecode rules only see code that runs **without** the application calling it; nested jars (fat jars) are not opened.
- Maven: only the main jar is analyzed (no classifier jars).
