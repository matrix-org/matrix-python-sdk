#!/usr/bin/env python
from setuptools import setup

setup(
    name="matrix-cs-python",
    version="0.0.1",
    description="Client-Server SDK for Matrix",
    author="matrix.org",
    author_email="kegan@matrix.org",
    url="https://github.com/matrix-org/matrix-python-sdk",
    packages = ['matrix'],
    license = "LICENSE",
    install_requires = [
        "requests"
    ],
)
