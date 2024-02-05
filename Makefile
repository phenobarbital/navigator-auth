venv:
	python3.10 -m venv .venv
	echo 'run `source .venv/bin/activate` to start develop Navigator-Auth'

install:
	pip install wheel==0.42.0
	pip install -e .

develop:
	pip install wheel==0.42.0
	pip install -e .
	pip install -Ur docs/requirements-dev.txt
	flit install --symlink

compile:
	python setup.py build_ext --inplace

release:
	lint test clean
	flit publish

format:
	python -m black navigator_auth

lint:
	python -m pylint --rcfile .pylintrc navigator_auth/*.py
	python -m black --check navigator_auth

test:
	python -m coverage run -m navigator_auth.tests
	python -m coverage report
	python -m mypy navigator_auth/*.py

perf:
	python -m unittest -v navigator_auth.tests.perf

distclean:
	rm -rf .venv
