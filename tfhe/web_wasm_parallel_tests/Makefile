test:
	npm install
	npm run build
	# This runs the server in background, saving its PID
	# to a file, so we can kill it when done
	{ npm run server > /dev/null & echo $$! > server.PID; }
	npm run test
	kill `cat server.PID` && rm server.PID

test-ci:
	npm install
	npm run build
	# This runs the server in background, saving its PID
	# to a file, so we can kill it when done
	{ npm run server > /dev/null & echo $$! > server.PID; }
	npm run test-separate-processes
	kill `cat server.PID` && rm server.PID


.PHONY: test
