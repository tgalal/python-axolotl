from __future__ import print_function
from setuptools import setup, find_packages
import axolotl

deps = ["protobuf>=2.6", "pycrypto", "python-axolotl-curve25519"]

setup(
    name='python-axolotl',
    version=axolotl.__version__ ,
    packages= find_packages(),
    install_requires = deps,
    license='GPLv3 License',
    author='Tarek Galal',
    author_email='tare2.galal@gmail.com',
    description="Python port of libaxolotl-android, originally written by Moxie Marlinspik",
    platforms='any'
)
