up:
	docker-compose -f docker-compose.yaml up -d --build

down:
	docker-compose -f docker-compose.yaml down

test:
	@echo "Running tests..."
	# Add your test commands here, e.g., using curl to test the nginx proxy
	curl -s http://localhost:7070/ || (echo "Check failed" && exit 1)