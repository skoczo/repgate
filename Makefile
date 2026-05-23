APP := repgate
IMAGE := repgate:dev

.PHONY: tidy build run test bench bench-report coverage docker-build docker-run clean

tidy:
	go mod tidy

build:
	mkdir -p bin
	go build -o bin/$(APP) ./cmd/repgate

run:
	go run ./cmd/repgate -c internal-config.yaml

test:
	go test ./...

test-integration:
	go test -tags=integration ./tests/integration/... -v

# benchmarks execution with reporting in a human-readable format
bench:
	@bash -lc 'set -o pipefail; go test ./internal/cache -run=^$$ -bench=. -benchmem -cpuprofile=cpu.out -memprofile=mem.out | tee bench.out'
	@echo "Generated profiles: cpu.out, mem.out"
	@echo "Benchmark output: bench.out"
	@echo "Inspect CPU profile: go tool pprof -http=:8081 cpu.out"
	@echo "Inspect memory profile: go tool pprof -http=:8082 mem.out"

bench-report: bench
	@echo "\n===== Benchmark summary ====="
	@grep -E '^(Benchmark|ok|PASS|FAIL)' bench.out || true
	@echo "\n===== CPU profile top lines ====="
	@go tool pprof -lines -top cpu.out | head -n 40
	@echo "\n===== CPU hot source lines ====="
	@go tool pprof -lines -list='.*' cpu.out | head -n 80
	@echo "\n===== Memory profile top lines ====="
	@go tool pprof -lines -top mem.out | head -n 40
	@echo "\n===== Memory hot source lines ====="
	@go tool pprof -lines -list='.*' mem.out | head -n 80

# tests with coverage in html format
coverage:
	go test ./... -covermode=count -coverprofile=coverage.out
	grep -v "github.com/skoczo/repgate/cmd/" coverage.out > coverage.clean.out && mv coverage.clean.out coverage.out
	go tool cover -func=coverage.out -o=coverage.func
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage HTML generated: coverage.html"

docker-build:
	docker buildx build --load -t $(IMAGE) .

docker-run:
	docker run --rm -p 8080:8080 $(IMAGE)

clean:
	rm -f bin/repgate cpu.out mem.out bench.out coverage.out coverage.html