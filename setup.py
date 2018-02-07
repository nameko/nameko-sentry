#!/usr/bin/env python
from setuptools import setup

setup(
    name='nameko-sentry',
    version='1.0.0',
    description='Nameko extension sends entrypoint exceptions to sentry',
    author='Matt Bennett',
    author_email='matt@bennett.name',
    url='http://github.com/mattbennett/nameko-sentry',
    py_modules=['nameko_sentry'],
    install_requires=[
        "nameko>=2.5.1",
        "raven>=3.0.0"
    ],
    extras_require={
        'dev': [
            "coverage==4.0.3",
            "flake8==3.3.0",
            "pylint==1.8.2",
            "pytest==2.8.3",
            "objgraph==3.1.0"
        ]
    },
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
