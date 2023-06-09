test: script = test
test-ci: script = test-separate-processes
bench: script = bench
bench-ci: script = bench-separate-processes

run_server:
	npm install
	npm run build
	# This runs the server in background, saving its PID
	# to a file, so we can kill it when done
	{ npm run server > /dev/null & echo $$! > server.PID; }
	npm run $(script)
	kill `cat server.PID` && rm server.PID

.PHONY: test # Run web client tests
test: run_server

.PHONY: test-ci  # Run web client tests in CI
test-ci: run_server

.PHONY: bench # Run benchmarks on web client
bench: run_server

.PHONY: bench-ci # Run benchmarks on web client in CI
bench-ci: run_server
