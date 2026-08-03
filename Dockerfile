FROM docker.io/library/golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ai-incident-recorder .

FROM docker.io/library/alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
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
