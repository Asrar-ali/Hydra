# Hydra — common tasks. See ARCHITECTURE.md and CLAUDE.md.
MODEL ?= mistral:7b

.PHONY: help run run-promptlock test dashboard setup arena-build falco-build clean

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

run:  ## run the adversarial loop (metamorphic mode) with the fake arena (no deps)
	HYDRA_FAKE=1 python3 -m referee.loop --iterations 8

run-promptlock:  ## run the adversarial loop (promptlock mode) with the fake arena (no deps)
	HYDRA_FAKE=1 python3 -m referee.loop --iterations 8 --mode promptlock

test:  ## run unit tests
	python3 -m unittest discover -s tests -v

dashboard:  ## serve the SSE dashboard at http://localhost:8000/
	python3 server.py

setup:  ## install host detector + pull the adversary model (manual, networked)
	brew install yara || true
	ollama pull $(MODEL) || true

arena-build:  ## build the sandbox container image
	docker build --no-cache -t hydra-arena ./arena

falco-build:  ## build the real Falco sensor image (needed for HYDRA_REAL_FALCO=1)
	docker build -t hydra-falco ./detectors/falco

clean:  ## remove generated files
	rm -f results.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
