.PHONY: clean test

clean:
	@find . -name '*.pyc' -exec rm -f {} +
	@find . -name '*.pyo' -exec rm -f {} +
	@find . '.coverage' -exec rm -f {}

test:
	@nosetests

coverage:
	@nosetests --with-coverage --cover-package=flask_rbac
