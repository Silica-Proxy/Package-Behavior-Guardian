# Package Behavior Guardian — Malicious Package Detection Service

[![SilicaProxy Logo](https://raw.githubusercontent.com/Silica-Proxy/Silica-Proxy/main/logo.png)](https://github.com/Silica-Proxy/Silica-Proxy)

Package Behavior Guardian analyzes **what a package does** (npm, PyPI, Maven) to catch a malicious release minutes after it is first requested, before any advisory lists it. Its main target is the **compromised legitimate package**: a well-known name whose new version steals credentials or runs a payload at install or load time.

It is an **asynchronous External Validation Service** of [SilicaProxy](https://github.com/Silica-Proxy/Silica-Proxy), next to [Package-Name-Guardian](https://github.com/Silica-Proxy/Package-Name-Guardian) (typosquatting).

> **Status:** only the **static pass** exists — no package code is ever executed. A sandboxed dynamic pass comes later. Run it in SilicaProxy with `blocking: false` until false positives have been measured.

---

## How it works

```
SilicaProxy ──POST /v1/check──► API ──► analysis_job (PostgreSQL queue)
     ▲            202 / 200                     │
     │                                          ▼
     │                               worker: download the whole version
     │                               static scanners ──► findings ──► verdict
     │                                          │
     └──── POST callbackUrl {verdict, reason} ◄─┘
```

1. **Intake** — both URLs are checked against host allowlists (anti-SSRF); each `(ecosystem, name, version)` is analyzed once. A version already analyzed answers `200` at once.
2. **Whole version** — the npm tarball, every PyPI file (sdist and wheels), the Maven main artifact (plus the requested file if it differs).
3. **Static scanners**:

   | Scanner | Ecosystems | Finding IDs |
   |---|---|---|
   | [GuardDog](https://github.com/DataDog/guarddog) 3.x | npm, PyPI | `GDG-RISK`, `GDG-<rule>` |
   | [malcontent](https://github.com/chainguard-dev/malcontent) | all | `BEH-071` / `072` / `073` |
   | Bytecode (ASM) | Maven | `JVM-001` … `JVM-007` |

4. **Verdict** — allowlisted findings are set aside; a `CRITICAL` blocks; otherwise `HIGH` (40) and `MEDIUM` (20) add up, each rule once, and a score ≥ 60 blocks (*manual review required*). The reason carries a report link.
5. **Callback** — `POST {callbackUrl}` with `Authorization: Bearer <api-key>`, retried with backoff.

A package that **prevents its own analysis** (malformed archive, zip bomb, oversized, scanner timeout) is **BLOCKED by `PBG-001`**. An infrastructure failure is retried, then marked `FAILED` without a verdict: SilicaProxy's `fail-open` policy applies.

### Rules

| ID | Detection | Severity |
|---|---|---|
| JVM-001 | Process execution in a static initializer or annotation processor | CRITICAL |
| JVM-002 | Class loading combined with Base64 / XOR decoding | CRITICAL |
| JVM-003 | Network call in a static initializer or annotation processor | HIGH |
| JVM-004 | Reads credential files (`.ssh`, `.aws`, `.npmrc`…) | HIGH |
| JVM-005 | Embedded native library loaded at run time | MEDIUM |
| JVM-006 | Annotation processor from an unknown publisher | MEDIUM |
| JVM-007 | Reflective process execution | CRITICAL / HIGH |
| PBG-001 | The package prevents its own analysis | CRITICAL |
| BEH-071 / 072 / 073 | malcontent rates a file CRITICAL / HIGH / MEDIUM | same |
| GDG-RISK | GuardDog rates the package `high_risk` / `suspicious` | CRITICAL / HIGH |
| GDG-&lt;rule&gt; | One GuardDog risk | HIGH / MEDIUM / LOW |

In a Maven plugin (Mojo), JVM-001, 003 and 007 are only MEDIUM. Calls made through reflection or method handles are not followed.

### Audit trail

Two append-only tables, with their own retention, read directly in the database (or through the `audit` logger):
- `analysis_audit` — one row per analysis attempt (`DONE`, `RETRY`, `FAILED`, `EXPIRED`, `ABANDONED`): timings, verdict, score and blocking rules as decided then.
- `check_audit` — one row per `POST /v1/check`, refused ones included.

```sql
SELECT finished_at, ecosystem, name, version, score, blocking_rules, reason
FROM analysis_audit WHERE verdict = 'BLOCKED' ORDER BY finished_at DESC LIMIT 50;
```

---

## API

| Endpoint | Key | Purpose |
|---|---|---|
| `POST /v1/check` | `security.api-key` | `202 PENDING` or `200 DONE` with the verdict |
| `GET /v1/reports?ecosystem=&name=&version=` | `security.report-api-key` (read-only) | Full report: files, findings, allowlisted findings |
| `/actuator/health`, `/actuator/prometheus` | — | Health and metrics |

```json
POST /v1/check
{ "packageName": "lodash", "version": "4.17.22", "ecosystem": "npm",
  "url": "https://registry.npmjs.org/lodash/-/lodash-4.17.22.tgz",
  "callbackUrl": "https://silica.internal/external-validation/callback/0b6c…" }
```

**Allowlist** — expected behaviors, in a reviewed file (`docker/allowlist.yaml`):

```yaml
packagebehaviorguardian:
  allowlist:
    - ecosystem: npm
      name: esbuild
      version: 0.25.0          # optional: without it, future releases are covered too
      rule-id: GDG-RISK        # optional
      detail: install hooks    # optional: substring of the finding
      reason: downloads its platform binary at install, reviewed 2026-10-28
```

Entries apply on restart, to versions already analyzed too.

---

## SilicaProxy configuration

```yaml
silicaproxy:
  external-validation:
    callback-base-url: "https://silica.internal"
    services:
      package-behavior-guardian:
        url: "https://pbg.internal/v1/check"
        api-key: "${PBG_API_KEY}"      # = packagebehaviorguardian.security.api-key
        mode: async
        fail-open: true
        blocking: false                # observation first
        cache-ttl-minutes: 20160
        pending-ttl-minutes: 120
```

---

## Configuration

Main properties, under `packagebehaviorguardian.*` — every other one is documented in `src/main/resources/application.yaml`.

| Property | Env variable | Default |
|---|---|---|
| `security.api-key` / `report-api-key` | `PACKAGEBEHAVIORGUARDIAN_API_KEY` / `_REPORT_API_KEY` | — (blank = refused) |
| `intake.allowed-callback-hosts` | `PACKAGEBEHAVIORGUARDIAN_CALLBACK_HOSTS` | empty = every check refused |
| `intake.allowed-artifact-hosts` | — | npm, PyPI, Maven Central |
| `queue.concurrency` | `PACKAGEBEHAVIORGUARDIAN_QUEUE_CONCURRENCY` | `4` |
| `analysis.high-weight` / `medium-weight` / `block-threshold` | `PACKAGEBEHAVIORGUARDIAN_HIGH_WEIGHT` / `_MEDIUM_WEIGHT` / `_BLOCK_THRESHOLD` | `40` / `20` / `60` (same on every instance) |
| `analysis.rule-set-version` | — | `2` (bump to re-analyze) |
| `analysis.public-base-url` | `PACKAGEBEHAVIORGUARDIAN_PUBLIC_BASE_URL` | — |
| `retention.days` / `analysis-audit-days` / `check-audit-days` | `PACKAGEBEHAVIORGUARDIAN_RETENTION_DAYS` / … | `90` / `365` / `365` |
| `allowlist` | — | `[]` |

---

## Deployment

Pre-built images are available on [Docker Hub](https://hub.docker.com/r/silicaproxy/packagebehaviorguardian).

```bash
docker build -t silicaproxy/packagebehaviorguardian .
cp docker/.env.example docker/.env
docker compose up -d                                     # PostgreSQL + 2 replicas
docker compose up -d --scale packagebehaviorguardian=4   # more capacity
```

Replicas are identical and stateless (queue in PostgreSQL, `SKIP LOCKED`), so they can be added or removed at any time. SilicaProxy calls `http://packagebehaviorguardian:8101/v1/check`.

**Scanner isolation** — in the image, GuardDog and malcontent run under a per-job unprivileged user, without the service's secrets (`docker/scanner-exec.c`). Keep `no-new-privileges` **off** on the container, or every scan fails.

Give the containers no network access beyond PostgreSQL, the registries and SilicaProxy.

**Licenses** — `./gradlew check` verifies every dependency license (`config/allowed-licenses.json`). malcontent always runs with `--third-party=false`. See `NOTICE`.

---

## Development

```bash
docker compose up -d     # PostgreSQL on localhost:5434
./gradlew bootRun        # port 8101
./gradlew check          # tests (Testcontainers), Checkstyle, PMD, SpotBugs, licenses
```

Dependencies are pinned: Gradle verification metadata (regenerate with `./gradlew --write-verification-metadata sha256 check bootJar`), Docker images by digest, GuardDog by hash (`docker/guarddog-requirements.txt`).

## Known limits

- Static pass only: an obfuscated payload that defeats the rules is not seen.
- Scoring is not calibrated yet: legitimate packages with install hooks (esbuild, requests) may need an allowlist entry.
- Nested jars (fat jars) and `war` / `ear` / `aar` bytecode are not inspected.
- Reflection and method handles are not followed by the bytecode rules.
