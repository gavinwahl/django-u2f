#!/usr/bin/env python
from setuptools import setup


setup(
    name='django-u2f',
    description="FIDO U2F security token support for Django",
    install_requires=[
        'django-argonauts',
        'django>=1.8',
        'qrcode',
        'six',
    ],
    # u2f support is an extra for now because m2crypt doesn't support python 3.
    # This allows using the rest of the authentication methods without u2f.
    extras_require={
        'u2f': ['python-u2flib-server'],
    },
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
