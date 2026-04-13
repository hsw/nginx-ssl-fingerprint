.PHONY: test-ja3-overflow test-ja3-overflow-logs test-ja3-overflow-down

# Build and run the JA3 overflow PoC test.
# nginx-asan logs will show AddressSanitizer errors if the bug is present.
test-ja3-overflow:
	docker compose up --build --abort-on-container-exit

# Show nginx-asan logs and grep for ASan errors.
test-ja3-overflow-logs:
	@docker compose logs nginx-asan 2>&1 | \
		grep -i "AddressSanitizer" && \
		echo "FAIL: AddressSanitizer errors detected" || \
		echo "PASS: no AddressSanitizer errors"

# Clean up containers and images.
test-ja3-overflow-down:
	docker compose down --rmi local
