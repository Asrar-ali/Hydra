# Hydra — common tasks. See ARCHITECTURE.md and CLAUDE.md.
MODEL ?= jimscard/whiterabbit-neo

.PHONY: help run test dashboard setup arena-build clean

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

run:  ## run the adversarial loop with the fake arena (no deps)
	HYDRA_FAKE=1 python3 -m referee.loop --iterations 8

test:  ## run unit tests
	python3 -m unittest discover -s tests -v

dashboard:  ## serve the SSE dashboard at http://localhost:8000/
	python3 server.py

setup:  ## install host detector + pull the adversary model (manual, networked)
	brew install yara || true
	ollama pull $(MODEL) || true

arena-build:  ## build the sandbox container image
	docker build --no-cache -t hydra-arena ./arena

clean:  ## remove generated files
	rm -f results.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
