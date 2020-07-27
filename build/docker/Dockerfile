ARG ALPINE_ARCH=

FROM golang:1.14.6
ARG BUILD_GOARCH=
ENV BUILD_GOARCH=${BUILD_GOARCH}
COPY . /spks
WORKDIR /spks/build
RUN go mod edit -replace=github.com/ctrl-cmd/gobuild=./gobuild
RUN GOARCH=${BUILD_GOARCH} go env
RUN BUILD_GOARCH=${BUILD_GOARCH} go run mage.go build

FROM ${ALPINE_ARCH}/alpine:3.12
COPY --from=0 ./spks/build/spks /usr/bin/
CMD ["/usr/bin/spks"]
