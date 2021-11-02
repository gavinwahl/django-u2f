#!/usr/bin/env python
import io
import os

from setuptools import setup, find_packages


def read(fname, encoding='utf-8'):
    path = os.path.join(os.path.dirname(__file__), fname)
    with io.open(path, encoding=encoding) as f:
        return f.read()


setup(
    name='django-u2f',
    version='0.3.1.dev0',
    description="FIDO U2F security token support for Django",
    long_description=read('README.rst'),
    url='https://github.com/gavinwahl/django-u2f',

    packages=find_packages(exclude=['testproj']),
    include_package_data=True,

    install_requires=[
        'python-u2flib-server>=5.0.0',
        'django-argonauts',
        'django>=1.11,<3.0.0',
        'qrcode',
        'six',
    ],
    author='Gavin Wahl',
    author_email='gavinwahl@gmail.com',
    license='BSD',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
    ],
)
