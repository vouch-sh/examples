.PHONY: test test-web test-spa test-native test-mcp test-a2a install report

test:
	cd tests && npm test

test-web:
	cd tests && npm run test:web

test-spa:
	cd tests && npm run test:spa

test-native:
	cd tests && npm run test:native

test-mcp:
	cd tests && npm run test:mcp

test-a2a:
	cd tests && npm run test:a2a

install:
	cd tests && npm install

report:
	cd tests && npm run report
