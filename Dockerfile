# Default to Go 1.24
ARG GO_VERSION=1.24
FROM golang:${GO_VERSION}-alpine AS build

RUN apk add git musl-dev mailcap

WORKDIR /go/src/github.com/morawskidotmy/transfer.ng

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go mod tidy
RUN CGO_ENABLED=0 go build -tags netgo -ldflags "-X github.com/morawskidotmy/transfer.ng/cmd.Version=$(git describe --tags 2>/dev/null || echo 'unknown') -a -s -w -extldflags '-static'" -o /go/bin/transfer.ng

ARG PUID=5000 \
    PGID=5000 \
    RUNAS

RUN mkdir -p /tmp/useradd /tmp/empty && \
    if [ ! -z "$RUNAS" ]; then \
    echo "${RUNAS}:x:${PUID}:${PGID}::/nonexistent:/sbin/nologin" >> /tmp/useradd/passwd && \
    echo "${RUNAS}:!:::::::" >> /tmp/useradd/shadow && \
    echo "${RUNAS}:x:${PGID}:" >> /tmp/useradd/group && \
    echo "${RUNAS}:!::" >> /tmp/useradd/groupshadow; else touch /tmp/useradd/unused; fi

FROM scratch AS final
LABEL maintainer="morawskidotmy" \
      org.opencontainers.image.title="transfer.ng" \
      org.opencontainers.image.description="Easy file sharing from the command-line" \
      org.opencontainers.image.source="https://github.com/morawskidotmy/transfer.ng"
ARG RUNAS

COPY --from=build /etc/mime.types /etc/mime.types
COPY --from=build /tmp/empty /tmp
COPY --from=build /tmp/useradd/* /etc/
COPY --from=build --chown=${RUNAS} /go/bin/transfer.ng /go/bin/transfer.ng
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

USER ${RUNAS}

ENTRYPOINT ["/go/bin/transfer.ng", "--listener", ":8080"]

EXPOSE 8080
