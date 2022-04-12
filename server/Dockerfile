FROM golang:alpine AS builder
WORKDIR $GOPATH/src/go-oauth2-server
COPY . .
RUN go build -o /go/bin/app *.go

FROM golang:alpine
WORKDIR /opt/static
COPY static .
WORKDIR /opt
COPY --from=builder /go/bin/app /bin/go-oauth2-server
EXPOSE 9096
ENTRYPOINT go-oauth2-server