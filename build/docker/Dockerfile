FROM --platform=$BUILDPLATFORM golang:1.14.6 AS build
ARG BUILDPLATFORM
ARG TARGETPLATFORM
COPY . /spks
WORKDIR /spks/build
RUN go mod edit -replace=github.com/ctrl-cmd/gobuild=./gobuild
RUN TARGETPLATFORM=$TARGETPLATFORM go run mage.go build

FROM busybox:1.32.0-musl
COPY --from=build ./spks/build/spks /usr/local/bin/
COPY --from=build ./spks/etc/server-example.yaml /usr/local/etc/spks/server.yaml
CMD ["/usr/local/bin/spks", "/usr/local/etc/spks/server.yaml"]
