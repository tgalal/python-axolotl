#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='libsignal',
    version='0.0.2',
    packages=find_packages(),
    install_requires=[
        'cryptography',
        'python-axolotl-curve25519',
        'protobuf>=3.6.0'
    ],
    license='GPLv3 License',
    description="Python port of libsignal-protocol-java",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/ForstaLabs/libsignal-python',
    platforms='any',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
