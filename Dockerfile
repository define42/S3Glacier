FROM golang:1.27.3 as builder

WORKDIR /app/

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY config/ config/
COPY bucket/ bucket/
COPY archive/ archive/
COPY autoclean/ autoclean/
COPY prometheus/ prometheus/
COPY *.go ./
COPY s3/ s3/
COPY gui/ gui/
COPY shared/ shared/
COPY static/ static/
RUN CGO_ENABLED=0 go test -tags=integration ./...
RUN CGO_ENABLED=0 go build -o /main
RUN chmod 777 /main

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /main /main
ENTRYPOINT ["/main"]
