.PHONY: run_server # Build and run Node server
run_server:
	npm ci
	npm run build
	npm run server

.PHONY: fmt # Format Javascript code
fmt:
	npm ci
	npm run format

.PHONY: check_fmt # Check Javascript code format
check_fmt:
	npm ci
	npm run check-format
