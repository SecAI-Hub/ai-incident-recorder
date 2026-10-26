FROM docker.io/library/golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ai-incident-recorder .

FROM docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
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
