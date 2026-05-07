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

# tests with coverage in html format
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

docker-build:
	docker buildx build --load -t $(IMAGE) .

docker-run:
	docker run --rm -p 8080:8080 $(IMAGE)

clean:
	rm bin/repgate