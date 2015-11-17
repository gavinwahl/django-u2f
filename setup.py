#!/usr/bin/env python
from setuptools import setup

setup(
    name='django-u2f',
    description="FIDO U2F security token support for Django",
    install_requires=[
        'django-argonauts',
        'python-u2flib-server',
        'django>=1.8',
    ],
    author='Gavin Wahl',
    author_email='gavinwahl@gmail.com',
    license='BSD',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
    ],
)
