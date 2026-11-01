# syntax=docker/dockerfile:1

# The single image of the service: the jar plus the external tools of the static pass (GuardDog,
# malcontent). Every instance answers SilicaProxy, analyzes queued jobs and sends callbacks.
#   docker build -t silicaproxy/packagebehaviorguardian .
# Same building blocks as SilicaProxy (Liberica JRE via jlink, Alpaquita runtime), but the glibc
# variants: malcontent only ships as a glibc binary.
# GuardDog's dependency pygit2 (GPL-2.0 with linking exception) runs as a separate process and is
# never linked to the Java code (see NOTICE).

# Base images are pinned by digest, the tag kept for readability: Dependabot (docker ecosystem)
# bumps the digest when the tag moves. GuardDog, pip and all their dependencies are pinned with
# hashes in docker/guarddog-*requirements.txt (how to regenerate: docker/guarddog-build-requirements.in).
# malcontent v1.28.0 (multi-arch index). cgr.dev only serves "latest" for free: pin by digest, and
# update the digest deliberately.
ARG MALCONTENT_IMAGE=cgr.dev/chainguard/malcontent@sha256:86d9f88b989610ad7b27e95619f839e1fc4b64ec71362a123772b104e9dd75da
# Ids of the scanner users (see docker/scanner-exec.c): the shared "scanner" group, then one user and
# group per job in flight (scanner1..scannerN), at least queue.concurrency of them.
ARG SCANNER_GID=10000
ARG SCANNER_FIRST_ID=10001
ARG SCANNER_SLOTS=64

FROM ${MALCONTENT_IMAGE} AS malcontent

# Stage 1: Build — bytecode is architecture-independent, so compile once on the native build platform
FROM --platform=$BUILDPLATFORM eclipse-temurin:25-jdk@sha256:83f4a7fc27df94dcc7b8de04d14cbbba8da14406f921e966969c3b09000aa507 AS builder
WORKDIR /app

COPY gradle/ /app/gradle/
COPY gradlew settings.gradle build.gradle /app/
COPY config/ /app/config/
COPY src/ /app/src/

# The Gradle wrapper and dependency caches persist across builds in a BuildKit cache mount
RUN --mount=type=cache,target=/root/.gradle \
    ./gradlew bootJar --no-daemon -x test && \
    cp build/libs/packagebehaviorguardian-*.jar /app/packagebehaviorguardian.jar

# Split the jar into Spring Boot layers, from the most stable to the most volatile
RUN java -Djarmode=tools -jar /app/packagebehaviorguardian.jar extract --layers --destination /app/extracted

# Stage 2: Minimal JRE with jlink (glibc, matches runtime base; the jdk-all variant ships the jmods jlink needs)
FROM bellsoft/liberica-runtime-container:jdk-all-25-glibc@sha256:db01f3f335b528cfce7f9044a11bf7b5e85ee94ec3c7eb92b42a3628d1e97c83 AS jre-builder
COPY --link --from=builder /app/packagebehaviorguardian.jar /app/packagebehaviorguardian.jar
RUN mkdir -p /tmp/app && \
    cd /tmp/app && \
    jar xf /app/packagebehaviorguardian.jar && \
    MODULES=$(jdeps \
        --ignore-missing-deps \
        --print-module-deps \
        --multi-release 25 \
        --class-path '/tmp/app/BOOT-INF/lib/*' \
        /tmp/app/BOOT-INF/classes \
        2>/dev/null) && \
    echo "Detected modules: $MODULES" && \
    jlink \
        --add-modules "${MODULES}" \
        --strip-debug \
        --no-man-pages \
        --no-header-files \
        --compress=zip-6 \
        --output /opt/jre

# Stage 2b: scanner-exec, the launcher that runs each scanner under its job's own uid instead of
# appuser's (docker/scanner-exec.c), with the ids of this image compiled in.
FROM bellsoft/alpaquita-linux-base:stream-glibc@sha256:e314a413e41ead31c714bd6bfaa9ee2162c530404f6888c2ceede17a81b7fad5 AS launcher-builder
ARG SCANNER_GID
ARG SCANNER_FIRST_ID
ARG SCANNER_SLOTS
RUN apk add --no-cache build-base linux-headers
COPY docker/scanner-exec.c /src/scanner-exec.c
RUN gcc -std=c11 -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie \
        -Wl,-z,relro,-z,now \
        -DFIRST_ID="${SCANNER_FIRST_ID}" -DSLOTS="${SCANNER_SLOTS}" -DSHARED_GID="${SCANNER_GID}" \
        -o /scanner-exec /src/scanner-exec.c

# Stage 3: GuardDog in a virtualenv. pygit2 (<1.19, pinned by GuardDog) and yara-python have no
# wheels for Alpaquita's Python, so they are compiled here against its libgit2 and OpenSSL.
# Every distribution is hash-checked (--require-hashes) and only what the locks list is installed
# (--no-deps); the sdists build without isolation, against the hash-checked build lock.
FROM bellsoft/alpaquita-linux-base:stream-glibc@sha256:e314a413e41ead31c714bd6bfaa9ee2162c530404f6888c2ceede17a81b7fad5 AS guarddog-builder
RUN apk add --no-cache python3 python3-dev py3-pip build-base libgit2-dev openssl-dev
COPY docker/guarddog-build-requirements.txt docker/guarddog-requirements.txt /tmp/
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m venv /opt/guarddog && \
    /opt/guarddog/bin/pip install --require-hashes --no-deps -r /tmp/guarddog-build-requirements.txt && \
    /opt/guarddog/bin/pip install --require-hashes --no-deps --no-build-isolation -r /tmp/guarddog-requirements.txt && \
    /opt/guarddog/bin/python -c "import pygit2, yara; print('pygit2', pygit2.__version__, 'yara-python', yara.__version__)"

# Stage 4: Runtime
FROM bellsoft/alpaquita-linux-base:stream-glibc@sha256:e314a413e41ead31c714bd6bfaa9ee2162c530404f6888c2ceede17a81b7fad5
ENV JAVA_HOME=/opt/jre
ENV PATH="$JAVA_HOME/bin:$PATH"
WORKDIR /app

# Runtime libraries of the compiled GuardDog extensions (same Python as the venv's)
RUN apk add --no-cache python3 libgit2 libcrypto3

# Run as non-root user; the application files stay owned by root and read-only for appuser.
# GuardDog rewrites its popular-packages cache on startup: it gets a writable copy, seeded with the
# lists shipped in its package, located by GUARDDOG_TOP_PACKAGES_CACHE_LOCATION below (ProcessRunner
# passes the GUARDDOG_* variables of this environment on to the guarddog process).
COPY --link --from=guarddog-builder /opt/guarddog /opt/guarddog
RUN ln -s /opt/guarddog/bin/guarddog /usr/local/bin/guarddog && \
    addgroup -S appgroup && adduser -S appuser -G appgroup && \
    mkdir -p /app/logs /app/work /var/cache/guarddog && \
    cp /opt/guarddog/lib/python3*/site-packages/guarddog/analyzer/metadata/resources/* /var/cache/guarddog/ && \
    chown -R appuser:appgroup /app/logs /app/work /var/cache/guarddog
ENV PACKAGEBEHAVIORGUARDIAN_WORK_DIR=/app/work
ENV GUARDDOG_TOP_PACKAGES_CACHE_LOCATION=/var/cache/guarddog

# The scanners never run as appuser, whose environment holds the secrets and who can reach every
# job's directory: scanner-exec runs each one as the user of its job (scanner1..N, one per job in
# flight; appuser belongs to their groups to hand them its job directories and delete what they
# leave). It is the only way to change uid in the image: CAP_SETUID/CAP_SETGID as file capabilities
# (no setuid root), executable by appgroup only, and every setuid/setgid bit of the base image is
# removed. Scanners may write only to their job's HOME (also their TMPDIR) and, through the shared
# "scanner" group, to GuardDog's cache: /tmp and /var/tmp are appgroup's, /app/work only lets them
# through to their own job directory, and /app/logs is closed (hs_err files list the JVM's environment).
ARG SCANNER_GID
ARG SCANNER_FIRST_ID
ARG SCANNER_SLOTS
COPY --link --from=launcher-builder /scanner-exec /usr/local/bin/scanner-exec
RUN apk add --no-cache --virtual .setcap libcap-utils && \
    addgroup -S -g "${SCANNER_GID}" scanner && \
    for i in $(seq 1 "${SCANNER_SLOTS}"); do \
        id=$((SCANNER_FIRST_ID + i - 1)) && \
        addgroup -S -g "${id}" "scanner${i}" && \
        adduser -S -D -H -h /nonexistent -s /sbin/nologin -u "${id}" -G "scanner${i}" "scanner${i}" && \
        addgroup appuser "scanner${i}" || exit 1; \
    done && \
    chown -R root:scanner /var/cache/guarddog && \
    chmod 2770 /var/cache/guarddog && chmod 0660 /var/cache/guarddog/* && \
    chmod 0711 /app/work && chmod 0700 /app/logs && \
    mkdir -p /var/tmp && chgrp appgroup /tmp /var/tmp && chmod 1770 /tmp /var/tmp && \
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod ug-s {} + && \
    chown root:appgroup /usr/local/bin/scanner-exec && chmod 0750 /usr/local/bin/scanner-exec && \
    setcap cap_setuid,cap_setgid=ep /usr/local/bin/scanner-exec && \
    apk del .setcap
ENV PACKAGEBEHAVIORGUARDIAN_SCANNERS_ISOLATION_FIRSTGID=${SCANNER_FIRST_ID}
ENV PACKAGEBEHAVIORGUARDIAN_SCANNERS_ISOLATION_SLOTS=${SCANNER_SLOTS}
ENV PACKAGEBEHAVIORGUARDIAN_SCANNERS_GUARDDOG_COMMAND=/usr/local/bin/scanner-exec,guarddog
ENV PACKAGEBEHAVIORGUARDIAN_SCANNERS_MALCONTENT_COMMAND=/usr/local/bin/scanner-exec,mal

COPY --link --from=malcontent /usr/bin/mal /usr/local/bin/mal
COPY --link --from=jre-builder /opt/jre /opt/jre
COPY --link --from=builder /app/extracted/dependencies/ /app/
COPY --link --from=builder /app/extracted/spring-boot-loader/ /app/
COPY --link --from=builder /app/extracted/snapshot-dependencies/ /app/
COPY --link --from=builder /app/extracted/application/ /app/

USER appuser

EXPOSE 8101

# Default JVM flags; override the whole variable to tune them (e.g. -e JDK_JAVA_OPTIONS="...").
# 60% of the container memory for the heap: GuardDog and malcontent run beside the JVM.
ENV JDK_JAVA_OPTIONS="-XX:+UseG1GC -XX:MaxRAMPercentage=60.0 -XX:+UseCompactObjectHeaders -XX:+UseStringDeduplication -Dsun.net.inetaddr.ttl=60 -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -XX:ErrorFile=/app/logs/hs_err_pid%p.log -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/app/logs"

ENTRYPOINT ["java", "-jar", "packagebehaviorguardian.jar"]
