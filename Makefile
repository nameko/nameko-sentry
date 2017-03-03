test: flake8 pytest

flake8:
	flake8 nameko_sentry.py test_nameko_sentry.py

pytest:
	coverage run --concurrency=eventlet --source nameko_sentry.py --branch -m pytest test_nameko_sentry.py
	coverage report --show-missing --fail-under=100
