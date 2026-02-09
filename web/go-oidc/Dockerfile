FROM golang:1.24-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go mod tidy && go build -o server .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY --from=build /app/server /usr/local/bin/

EXPOSE 3000
CMD ["server"]
