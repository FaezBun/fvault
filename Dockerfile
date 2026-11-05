# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/fvault ./cmd/fvault

FROM alpine:3.22
RUN apk add --no-cache ca-certificates \
    && addgroup -S fvault \
    && adduser -S -u 1000 -G fvault fvault \
    && mkdir -p /data \
    && chown fvault:fvault /data
WORKDIR /app
COPY --from=build /out/fvault /usr/local/bin/fvault
COPY templates/ /app/templates/
COPY static/ /app/static/
ENV FVAULT_HOME=/data \
    FVAULT_HOST=0.0.0.0 \
    FVAULT_PORT=17384
VOLUME /data
EXPOSE 17384
USER fvault
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:17384/healthz || exit 1
ENTRYPOINT ["fvault"]
CMD ["serve"]
