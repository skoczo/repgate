APP := repgate
IMAGE := repgate:dev

.PHONY: tidy build run test docker-build docker-run

tidy:
	go mod tidy

build:
	mkdir -p bin
	go build -o bin/$(APP) ./cmd/repgate

run:
	go run ./cmd/repgate

test:
	go test ./...

docker-build:
	docker buildx build --load -t $(IMAGE) .

docker-run:
	docker run --rm -p 8080:8080 $(IMAGE)