# Navigator-Auth Makefile

.PHONY: venv install develop release format lint test clean distclean lock sync check-deps

# Python version to use
PYTHON_VERSION := 3.11

# Auto-detect available tools
HAS_UV := $(shell command -v uv 2> /dev/null)

# Install uv if missing
install-uv:
	curl -LsSf https://astral.sh/uv/install.sh | sh
	@echo "uv installed! You may need to restart your shell or run 'source ~/.bashrc'"

# Create virtual environment
venv:
	uv venv --python $(PYTHON_VERSION) .venv
	@echo 'run `source .venv/bin/activate` to start develop Navigator-Auth'

# Install production dependencies using lock file
install:
	uv sync --frozen --no-dev
	@echo "Production dependencies installed."

# Generate lock files
lock:
ifdef HAS_UV
	uv lock
else
	@echo "Lock files require uv. Install with: make install-uv"
endif

# Install all dependencies including dev dependencies
develop:
	uv sync --frozen --extra uvloop --dev

# Alternative: install without lock file (faster for development)
develop-fast:
	uv pip install -e .[uvloop]
	uv pip install -e .[dev]

# Compile Cython extensions
compile:
	python setup.py build_ext --inplace

# Build and publish release
release: lint test clean
	uv build
	uv publish

# Format code
format:
	uv run black navigator_auth

# Lint code
lint:
	uv run pylint --rcfile .pylintrc navigator_auth/*.py
	uv run black --check navigator_auth

# Run tests
test:
	uv run coverage run -m pytest tests
	uv run coverage report
	uv run mypy navigator_auth/*.py

# Performance tests
perf:
	uv run python -m unittest -v navigator_auth.tests.perf

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name "*.so" -delete
	find . -type d -name __pycache__ -delete
	@echo "Clean complete."

# Remove virtual environment
distclean:
	rm -rf .venv
	rm -rf uv.lock

# Show project info
info:
	uv tree
