FROM docker.io/library/golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ai-incident-recorder .

FROM docker.io/library/alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN mkdir -p /var/lib/secure-ai/incidents /var/lib/secure-ai/logs && \
    chown -R 65534:65534 /var/lib/secure-ai
COPY --from=build /ai-incident-recorder /usr/local/bin/ai-incident-recorder
COPY policies/default-policy.yaml /etc/secure-ai/policy/recorder.yaml
USER 65534:65534
EXPOSE 8495
VOLUME ["/var/lib/secure-ai"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 CMD wget -q -T 3 -O - http://127.0.0.1:8495/health >/dev/null || exit 1
ENTRYPOINT ["ai-incident-recorder"]
CMD ["record"]
