FROM golang:alpine AS builder
WORKDIR $GOPATH/src/go-oauth2-client
COPY . .
RUN go build -o /go/bin/app *.go

FROM golang:alpine
COPY --from=builder /go/bin/app /bin/go-oauth2-client
EXPOSE 9094
ENTRYPOINT go-oauth2-client