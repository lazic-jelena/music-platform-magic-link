FROM golang:1.22-alpine AS build
WORKDIR /src

COPY go.* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/app .

FROM alpine:3.20
RUN adduser -D -H appuser
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=build /out/app /app/app

ENV PORT=8080
EXPOSE 8080

USER appuser
ENTRYPOINT ["/app/app"]
