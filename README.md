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

1. **Intake.** `url` and `callbackUrl` are checked against host allowlists (anti-SSRF), the version is queued once per `(ecosystem, name, version)`, and the callback URL is recorded. A version already analyzed under the current rule set answers `200` with its verdict, and the verdict is also delivered to the callback (SilicaProxy's async client ignores the response body).
2. **Whole version.** SilicaProxy caches one verdict per version, whatever file was asked first, so the analysis covers the version, not just that file: the npm tarball; **every** PyPI file (sdist and all wheels, yanked ones included: pip still installs them when the version is pinned); for Maven, the main artifact given by the POM's `<packaging>` (`jar`, `war`, `aar`…; none for `pom`), plus the requested file when it is another archive (a classifier jar). A file that should exist but does not fails the job instead of passing.
3. **Static scanners** (each one can be disabled):

   | Scanner | Ecosystems | What it does | Finding IDs |
   |---|---|---|---|
   | [GuardDog](https://github.com/DataDog/guarddog) 3.x (Datadog, Apache-2.0) | npm, PyPI | YARA threat/capability rules on code and metadata, correlated into a package rating | `GDG-RISK`, `GDG-<rule>` |
   | [malcontent](https://github.com/chainguard-dev/malcontent) (Chainguard, Apache-2.0) | all | Capability YARA rules, including binaries | `BEH-071` |
   | Bytecode (ASM, in-process) | Maven | Calls in static initializers, annotation processors, Mojos… | `JVM-001` … `JVM-007` |

4. **Verdict** (two verdicts only): findings covered by the allowlist are set aside, then one `CRITICAL` blocks; otherwise `HIGH` (40) and `MEDIUM` (15) add up, each rule once, and a score ≥ 60 blocks with *"manual review required"*. The reason carries a report link.
5. **Callback** `POST {callbackUrl}` with `Authorization: Bearer <api-key>`, retried with exponential backoff. `404`/`410` means SilicaProxy no longer waits for that token (already resolved, or expired) and the callback is dropped.

A package that **prevents its own analysis** — malformed class file, archive beyond the zip-bomb limits, file over `max-size-mb`, version over 1 GB or 60 files, scanner flooding its output, scanner timing out on the last attempt — is **BLOCKED by `PBG-001`** (otherwise a hostile archive would be enough to fall back on SilicaProxy's fail-open). An **infrastructure** failure (registry or database unreachable, tool missing) is retried, then marked `FAILED` without a verdict: SilicaProxy's pending entry times out and its `fail-open` policy applies; the next check of that version queues it again.

### Rules

| ID | Detection | Severity |
|---|---|---|
| JVM-001 | `Runtime.exec` / `ProcessBuilder.start` in a static initializer or an annotation processor (MEDIUM in a Maven Mojo) | CRITICAL |
| JVM-002 | `defineClass` / `URLClassLoader` in a method that Base64-decodes or XORs | CRITICAL |
| JVM-003 | Network call (`URL.openConnection`, `Socket`, `HttpClient`, `InetAddress.getByName`) in a static initializer or an annotation processor (MEDIUM in a Mojo) | HIGH |
| JVM-004 | Reads `user.home` and refers to a credential path (`.ssh`, `.aws`, `.m2/settings.xml`, `.npmrc`…) | HIGH |
| JVM-005 | Embedded native library **and** `System.load`/`loadLibrary` | MEDIUM |
| JVM-006 | Annotation processor declared by a publisher outside `known-annotation-processor-groups` | MEDIUM |
| JVM-007 | Reflective call (`Method.invoke`, `MethodHandle`, `Lookup.find*`) reachable from a static initializer or a processor, with the process-execution names in clear (MEDIUM in a Mojo) — HIGH when the names are decoded at run time (Base64 / XOR) | CRITICAL |
| PBG-001 | The package prevents its own analysis (see above) | CRITICAL |
| BEH-071 | malcontent: a file rated CRITICAL | CRITICAL |
| GDG-RISK | GuardDog package rating `high_risk` / `suspicious` | CRITICAL / HIGH |
| GDG-&lt;rule&gt; | One GuardDog risk (detail for the report, does not count) | LOW |

JVM-001, 003 and 007 follow calls through the jar's own classes, lambdas included (`static { Helper.run(); }` with the payload in `Helper`); a Mojo is any class extending `AbstractMojo` or declared in `META-INF/maven/plugin.xml`. In a Maven Mojo they are only MEDIUM: plugins legitimately spawn processes and download tools (exec-maven-plugin, frontend-maven-plugin).

---

## API

| Endpoint | Key (`Authorization: Bearer …`) | Purpose |
|---|---|---|
| `POST /v1/check` | `security.api-key`, held by SilicaProxy and also sent on callbacks | SilicaProxy async contract: `202 {"status":"PENDING"}` or `200 {"status":"DONE","verdict":…,"reason":…}` |
| `GET /v1/reports?ecosystem=&name=&version=` | `security.report-api-key`, read-only — never the check key, which could forge callbacks | Full report: files and SHA-256, findings, allowlisted findings, last error |
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
      rule-id: GDG-RISK          # optional: every rule when absent
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
| `queue.concurrency` / `max-attempts` / `max-wait-minutes` | `PACKAGEBEHAVIORGUARDIAN_QUEUE_CONCURRENCY` | `4` / `3` / `30` | Jobs per instance, attempts before FAILED, health threshold |
| `analysis.rule-set-version` | — | `1` | Bump when rules change: older results are re-analyzed on the next check |
| `analysis.public-base-url` | `PACKAGEBEHAVIORGUARDIAN_PUBLIC_BASE_URL` | — | Base of the report link in reasons |
| `scanners.guarddog.*` | — | enabled | `command`, `timeout-seconds` |
| `scanners.malcontent.*` | — | enabled | `command`, `timeout-seconds`, `third-party-rules` (**false**) |
| `scanners.bytecode.*` | — | enabled | `known-annotation-processor-groups` |
| `artifact.max-size-mb` / `max-files-per-version` / `work-dir` | `PACKAGEBEHAVIORGUARDIAN_WORK_DIR` | `200` / `60` / tmp | Download limits and scratch directory |
| `allowlist` | — | `[]` | Expected behaviors (see [API](#api)) |

---

## Deployment

One image, which holds the jar and the tools of the static pass. It uses SilicaProxy's building blocks, in their glibc variants since malcontent only ships as a glibc binary: a jlink'ed Liberica 25 JRE on Alpaquita Linux (`stream-glibc`), Python 3.14 from Alpaquita, GuardDog 3.2.0 in a virtualenv (pygit2 and yara-python compiled against Alpaquita's libgit2 and OpenSSL), malcontent 1.28.0.

```bash
docker build -t silicaproxy/packagebehaviorguardian .
```

Every replica is identical: it answers SilicaProxy, analyzes queued jobs and sends callbacks. Replicas are stateless: jobs and callbacks are claimed with `SELECT … FOR UPDATE SKIP LOCKED`, and a job whose replica died is taken over when its lease expires, so replicas can be added or removed at any time. Capacity is replicas × `queue.concurrency` analyses at a time.

`docker/compose.yaml` deploys PostgreSQL and 2 replicas, joined to SilicaProxy's Docker network (`cp docker/.env.example docker/.env` first; the SilicaProxy-side settings are listed at the end of that file). SilicaProxy calls `http://packagebehaviorguardian:8101/v1/check`.

```bash
docker compose up -d                                     # PostgreSQL + PBG_REPLICAS replicas (2)
docker compose up -d --scale packagebehaviorguardian=4   # more analysis capacity
```

Keep `PBG_REPLICAS × PBG_DB_POOL_SIZE` below `PBG_POSTGRES_MAX_CONNECTIONS`, and `PBG_CONCURRENCY` at about half the CPUs of a container. Run end to end with two replicas (2026-10-28): work is shared between them and each callback is delivered exactly once.

The static pass never executes package code, but it parses hostile archives: give the containers no access to the internal network beyond PostgreSQL, the registries and SilicaProxy, and no secrets other than their own.

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

### Known limits and points to check

- **Checked on real packages** (2026-10-28, Docker image: Python 3.14.10, GuardDog 3.2.0, pygit2 1.18.2, yara-python 4.5.4, malcontent 1.28.0): left-pad, esbuild, requests (sdist + wheel), guava, lombok, exec-maven-plugin, sqlite-jdbc, zstd-jni, jackson-bom are all ALLOWED (esbuild and requests score 40: GuardDog rates them *suspicious* for their install hooks / test fixtures; exec-maven-plugin and the JNI jars score 15). A synthetic npm package that evals base64, serializes `process.env` and runs a detached `curl | sh` is rated `high_risk` (9.4/10) by GuardDog: BLOCKED. The JSON formats of both tools match the parsers. Re-check them whenever the pinned versions change.
- GuardDog loads its typosquatting rule (and refreshes its popular-packages cache, over the network when stale) even for local scans: the image points `GUARDDOG_TOP_PACKAGES_CACHE_LOCATION` at a writable copy.
- **Scoring is not calibrated yet**: on npm/PyPI the only non-CRITICAL signal is GuardDog's `suspicious` rating (40), so the 60 threshold is never reached there without a CRITICAL. Whether malcontent's HIGH behaviors should count too is to be decided on the observation-phase data (false-positive risk: esbuild and requests already score 40).
- Only the **static** pass: an obfuscated payload that defeats the YARA rules and the bytecode rules is not seen until the dynamic pass.
- Bytecode rules only see code that runs **without** the application calling it; nested jars (fat jars) are not opened.
- Maven: only the main jar is analyzed (no classifier jars).
