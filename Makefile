test: flake8 pylint pytest

flake8:
	flake8 nameko_sentry.py test_nameko_sentry.py

pylint:
	pylint nameko_sentry -E

pytest:
	pytest --cov -vv
	coverage report --show-missing --fail-under=100
