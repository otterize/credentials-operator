FROM golang:1.21-alpine as builder
RUN apk add --no-cache ca-certificates git protoc
RUN apk add build-base

WORKDIR /workspace
# Copy the Go Modules manifests
COPY ./operator/go.mod ./operator/go.sum ./

#RUN go mod download

COPY ./operator ./operator
COPY ./intents-operator ./intents-operator
#RUN #cd operator
ARG TARGETOS
ARG TARGETARCH
#RUN go test -v ./...
RUN ls -ltr
RUN ls -ltr && cd operator && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -a -o /workspace/manager ./main.go

# add version file
ARG VERSION
RUN echo -n $VERSION > /version

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM alpine
WORKDIR /
COPY --from=builder /workspace/manager .
#USER 65532:65532
COPY --from=builder /version .

ENTRYPOINT ["/manager"]