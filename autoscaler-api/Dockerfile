FROM golang:1.14.2
WORKDIR /go/src/phdata.io/autoscaler-api/
COPY main.go .
COPY provider.go .
COPY go.mod .
RUN go get -v
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .
ENTRYPOINT ["./main"]