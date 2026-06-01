FROM node:20-alpine AS node-builder

WORKDIR /app/web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build

FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=node-builder /app/web/dist ./web/dist

RUN CGO_ENABLED=0 GOOS=linux go build -o /repgate ./cmd/repgate

FROM alpine:latest

WORKDIR /app

COPY --from=builder /repgate /app/repgate

# copy db migrations
COPY --from=builder /app/db/migrations /app/db/migrations

# Create data directory with permissions before switching to nobody user
RUN mkdir -p /app/data && chmod 777 /app/data

EXPOSE 8080

USER nobody

ENTRYPOINT ["/app/repgate"]