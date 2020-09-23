
# Build the application
FROM golang:1.9 as builder

WORKDIR /Users/nickpileggi/go/src/phdata.io/k8s-scaling-app
COPY main.go .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Run the application
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/
COPY --from=builder /Users/nickpileggi/go/src/phdata.io/k8s-scaling-app/main .

ENTRYPOINT ["./main"]


