# One image holds both binaries: replaydiff, the entrypoint, and replaydiff-fixture,
# the synthetic service used by demos and tests. Base images are pinned by digest.

FROM golang:1.27.3-alpine@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/Bispulm/replaydiff/internal/cli.Version=${VERSION}" \
        -o /out/bin/replaydiff ./cmd/replaydiff \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bin/replaydiff-fixture ./cmd/replaydiff-fixture \
    && mkdir -p /out/state

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/bin/ /usr/local/bin/
# Owned by the runtime user, so a new volume mounted here starts out writable.
COPY --from=build --chown=65532:65532 /out/state /var/lib/replaydiff
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/replaydiff"]
