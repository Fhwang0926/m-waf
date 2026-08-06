# syntax=docker/dockerfile:1.7
ARG GO_IMAGE=golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

FROM ${GO_IMAGE} AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
COPY web ./web
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG BUNDLE_VERSION=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X github.com/Fhwang0926/m-waf/internal/version.Version=${VERSION} -X github.com/Fhwang0926/m-waf/internal/version.Commit=${COMMIT} -X github.com/Fhwang0926/m-waf/internal/version.BuildDate=${BUILD_DATE} -X github.com/Fhwang0926/m-waf/internal/version.BundleVersion=${BUNDLE_VERSION}" \
    -o /out/mwaf-manager ./cmd/mwaf-manager

FROM ${RUNTIME_IMAGE}
ARG SOURCE_URL=https://github.com/Fhwang0926/m-waf
ARG COMMIT=unknown
LABEL org.opencontainers.image.source=${SOURCE_URL} \
      org.opencontainers.image.revision=${COMMIT} \
      org.opencontainers.image.title="M-WAF Manager" \
      org.opencontainers.image.description="M-WAF control plane with embedded Agent and ModSecurity package bundle"
COPY --from=builder --chown=65532:65532 /out/mwaf-manager /usr/local/bin/mwaf-manager
COPY --chown=65532:65532 dist/bundle/ /opt/mwaf/bundles/current/
COPY --chown=65532:65532 dist/package-signing.pub /etc/mwaf-manager/package-signing.pub
COPY --chown=65532:65532 dist/empty/ /var/lib/mwaf-manager/
COPY --chown=65532:65532 dist/empty/ /var/log/mwaf-manager/
USER 65532:65532
EXPOSE 8443 9443
ENTRYPOINT ["/usr/local/bin/mwaf-manager"]
