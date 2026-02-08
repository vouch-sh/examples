FROM golang:1.23-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o server .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates
COPY --from=build /app/server /usr/local/bin/

EXPOSE 3000
CMD ["server"]
