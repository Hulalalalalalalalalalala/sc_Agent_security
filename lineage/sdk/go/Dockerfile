FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod /src/
COPY lctsdk /src/lctsdk
COPY cmd /src/cmd
RUN CGO_ENABLED=0 go build -o /out/go-lct-agent ./cmd/example_agent

FROM alpine:3.20
COPY --from=builder /out/go-lct-agent /usr/local/bin/go-lct-agent
ENTRYPOINT ["/usr/local/bin/go-lct-agent", "-port", "9001"]
