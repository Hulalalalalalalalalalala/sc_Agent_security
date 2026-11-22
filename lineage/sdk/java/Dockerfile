FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /src
COPY LCTSidecarClient.java /src/
RUN mkdir -p /out && javac -d /out /src/LCTSidecarClient.java

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=builder /out /app
ENTRYPOINT ["java", "-cp", "/app", "LCTSidecarClient"]
