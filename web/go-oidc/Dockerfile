FROM golang:1.26-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -o server .

FROM alpine:3.23

RUN apk add --no-cache ca-certificates
COPY --from=build /app/server /usr/local/bin/

EXPOSE 3000
CMD ["server"]
