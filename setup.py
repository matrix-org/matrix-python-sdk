#!/usr/bin/env python
from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))


def read_file(names, encoding='utf-8'):
    file_path = os.path.join(here, *names)
    if encoding:
        with codecs.open(file_path, encoding=encoding) as f:
            return f.read()
    else:
        with open(file_path, 'rb') as f:
            return f.read()


def exec_file(names):
    code = read_file(names, encoding=None)
    result = {}
    exec(code, result)
    return result


setup(
    name='matrix_client',
    version=exec_file(('matrix_client', '__init__.py',))['__version__'],
    description='Client-Server SDK for Matrix',
    long_description=read_file(('README.rst',)),
    long_description_content_type="text/x-rst",
    author='The Matrix.org Team',
    author_email='team@matrix.org',
    url='https://github.com/matrix-org/matrix-python-sdk',
    packages=find_packages(),
    license='Apache License, Version 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Communications :: Chat',
        'Topic :: Communications :: Conferencing',
    ],
    keywords='chat sdk matrix matrix.org',
    install_requires=[
        'requests',
        'urllib3',
    ],
    setup_requires=['pytest-runner',],
    tests_require=['pytest', 'responses',],
    extras_require={
        'test': ['pytest', 'responses'],
        'doc': ['Sphinx==1.4.6', 'sphinx-rtd-theme==0.1.9', 'sphinxcontrib-napoleon==0.5.3'],
        'format': ['flake8'],
        'e2e': ['python-olm==dev', 'canonicaljson']
    },
    dependency_links=[
        'git+https://github.com/poljar/python-olm.git@4752eb22f005cb9f6143857008572e6d83252841#egg=python-olm-dev'
    ]
)
