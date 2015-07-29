#!/usr/bin/env python
from setuptools import setup

setup(
    name='nameko-sentry',
    version='0.0.1',
    description='Nameko extension sends entrypoint exceptions to sentry',
    author='Matt Bennett',
    author_email='matt@bennett.name',
    url='http://github.com/mattbennett/nameko-sentry',
    py_modules=['nameko_sentry'],
    install_requires=[
        "nameko>=2.0.0",
        "raven>=3.0.0"
    ],
    extras_require={
        'dev': [
            "coverage==4.0a1",
            "flake8==2.1.0",
            "mccabe==0.3",
            "pep8==1.6.1",
            "pyflakes==0.8.1",
            "pylint==1.0.0",
            "pytest==2.4.2",
        ]
    },
    dependency_links=[],
    zip_safe=True,
    license='Apache License, Version 2.0',
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Intended Audience :: Developers",
    ]
)
