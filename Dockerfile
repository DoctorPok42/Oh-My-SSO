# syntax=docker/dockerfile:1
# ==============================================================================
# Oh-My-SSO servers: one build, two images (targets), and the migrations.
#   docker build --target idp       -t oh-my-sso-idp .
#   docker build --target idp-admin -t oh-my-sso-idp-admin .
#   docker build --target migrate   -t oh-my-sso-migrate .
# Static binaries (CGO off) on a "distroless" base: no shell, no package
# manager, a non-root user. https://github.com/GoogleContainerTools/distroless
# Templates, login pages and dev pages are embedded in the binaries (go:embed).
# ==============================================================================
ARG GO_VERSION=1.26.11

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
HEALTHCHECK --interval=15s --timeout=8s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/idp", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/idp"]

# Admin side: Admin API (port 8090) + bootstrap / break-glass commands.
FROM gcr.io/distroless/static-debian12:nonroot AS idp-admin
COPY --from=build /out/idp-admin /usr/local/bin/idp-admin
USER nonroot:nonroot
EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=8s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/idp-admin", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/idp-admin"]
CMD ["serve"]

# Database migrations, at the version of the code: the image of a tag holds
# the migrations of that commit, so a deploy of an older tag never applies the
# ones of a newer commit. Used by the "migrate" service of compose.yml
# (atlas migrate apply), before idp and idp-admin start.
FROM arigaio/atlas:1.3.3-community AS migrate
COPY ent/migrate/migrations /migrations
