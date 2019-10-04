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
        'requests~=2.22',
        'urllib3~=1.21',
    ],
    setup_requires=['pytest-runner~=5.1'],
    tests_require=['pytest >=4.6.5, <6.0.0', 'responses >=0.10.6, ==0.10.*'],
    extras_require={
        'test': ['pytest >=4.6, <6.0.0', 'responses >=0.10.6, ==0.10.*'],
        'doc': ['Sphinx >=1.7.6, ==1.*', 'sphinx-rtd-theme >=0.1.9, ==0.1.*',
                'sphinxcontrib-napoleon >=0.5.3, ==0.5.*'],
        'e2e': ['python-olm~=3.1', 'canonicaljson~=1.1']
    },
)
