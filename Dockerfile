# syntax=docker/dockerfile:1

# The single image of the service: the jar plus the external tools of the static pass (GuardDog,
# malcontent). Every instance answers SilicaProxy, analyzes queued jobs and sends callbacks.
#   docker build -t silicaproxy/packagebehaviorguardian .
# Same building blocks as SilicaProxy (Liberica JRE via jlink, Alpaquita runtime), but the glibc
# variants: malcontent only ships as a glibc binary.
# GuardDog's dependency pygit2 (GPL-2.0 with linking exception) runs as a separate process and is
# never linked to the Java code (see NOTICE).

ARG GUARDDOG_VERSION=3.2.0
ARG PIP_VERSION=26.2.2
# malcontent v1.28.0 (multi-arch index). cgr.dev only serves "latest" for free: pin by digest, and
# update the digest deliberately.
ARG MALCONTENT_IMAGE=cgr.dev/chainguard/malcontent@sha256:86d9f88b989610ad7b27e95619f839e1fc4b64ec71362a123772b104e9dd75da

FROM ${MALCONTENT_IMAGE} AS malcontent

# Stage 1: Build — bytecode is architecture-independent, so compile once on the native build platform
FROM --platform=$BUILDPLATFORM eclipse-temurin:25-jdk AS builder
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
FROM bellsoft/liberica-runtime-container:jdk-all-25-glibc AS jre-builder
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

# Stage 3: GuardDog in a virtualenv. pygit2 (<1.19, pinned by GuardDog) and yara-python have no
# wheels for Alpaquita's Python, so they are compiled here against its libgit2 and OpenSSL.
FROM bellsoft/alpaquita-linux-base:stream-glibc AS guarddog-builder
ARG GUARDDOG_VERSION
ARG PIP_VERSION
RUN apk add --no-cache python3 python3-dev py3-pip build-base libgit2-dev openssl-dev
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m venv /opt/guarddog && \
    /opt/guarddog/bin/pip install "pip==${PIP_VERSION}" && \
    /opt/guarddog/bin/pip install "guarddog==${GUARDDOG_VERSION}" && \
    /opt/guarddog/bin/python -c "import pygit2, yara; print('pygit2', pygit2.__version__, 'yara-python', yara.__version__)"

# Stage 4: Runtime
FROM bellsoft/alpaquita-linux-base:stream-glibc
ENV JAVA_HOME=/opt/jre
ENV PATH="$JAVA_HOME/bin:$PATH"
WORKDIR /app

# Runtime libraries of the compiled GuardDog extensions (same Python as the venv's)
RUN apk add --no-cache python3 libgit2 libcrypto3

# Run as non-root user; the application files stay owned by root and read-only for appuser.
# GuardDog rewrites its popular-packages cache on startup: it gets a writable copy, seeded with the
# lists shipped in its package (see scanners.guarddog.environment).
COPY --link --from=guarddog-builder /opt/guarddog /opt/guarddog
RUN ln -s /opt/guarddog/bin/guarddog /usr/local/bin/guarddog && \
    addgroup -S appgroup && adduser -S appuser -G appgroup && \
    mkdir -p /app/logs /app/work /var/cache/guarddog && \
    cp /opt/guarddog/lib/python3*/site-packages/guarddog/analyzer/metadata/resources/* /var/cache/guarddog/ && \
    chown -R appuser:appgroup /app/logs /app/work /var/cache/guarddog
ENV PACKAGEBEHAVIORGUARDIAN_WORK_DIR=/app/work
ENV GUARDDOG_TOP_PACKAGES_CACHE_LOCATION=/var/cache/guarddog

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
ENV JDK_JAVA_OPTIONS="-XX:+UseG1GC -XX:MaxRAMPercentage=60.0 -XX:+UseCompactObjectHeaders -XX:+UseStringDeduplication -Dsun.net.inetaddr.ttl=60 -XX:ErrorFile=/app/logs/hs_err_pid%p.log -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/app/logs"

ENTRYPOINT ["java", "-jar", "packagebehaviorguardian.jar"]
