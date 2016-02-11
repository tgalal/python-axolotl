from __future__ import print_function

import sys

import axolotl
from setuptools import find_packages, setup

deps = ['pycrypto', 'python-axolotl-curve25519']

if sys.version_info < (3, 0):
    deps += ['protobuf>=2.6,<3.0.0-alpha-2']
else:
    deps += ['protobuf==3.0.0.b2']

setup(
    name='python-axolotl',
    version=axolotl.__version__,
    packages=find_packages(),
    install_requires=deps,
    license='GPLv3 License',
    author='Tarek Galal',
    author_email='tare2.galal@gmail.com',
    description='Python port of libaxolotl-android, originally written by Moxie Marlinspik',
    platforms='any')
