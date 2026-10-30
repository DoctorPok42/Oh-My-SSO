# syntax=docker/dockerfile:1
# ==============================================================================
# Oh-My-SSO servers: one build, two images (targets).
#   docker build --target idp       -t oh-my-sso-idp .
#   docker build --target idp-admin -t oh-my-sso-idp-admin .
# Static binaries (CGO off) on a "distroless" base: no shell, no package
# manager, a non-root user. https://github.com/GoogleContainerTools/distroless
# Templates, login pages and dev pages are embedded in the binaries (go:embed).
# ==============================================================================
ARG GO_VERSION=1.26.10

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/idp ./cmd/idp && \
    go build -trimpath -ldflags="-s -w" -o /out/idp-admin ./cmd/idp-admin

# Public server: OIDC, SAML, login pages, account panel. Port 8080.
FROM gcr.io/distroless/static-debian12:nonroot AS idp
COPY --from=build /out/idp /usr/local/bin/idp
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/idp"]

# Admin side: Admin API (port 8090) + bootstrap / break-glass commands.
FROM gcr.io/distroless/static-debian12:nonroot AS idp-admin
COPY --from=build /out/idp-admin /usr/local/bin/idp-admin
USER nonroot:nonroot
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/idp-admin"]
CMD ["serve"]
