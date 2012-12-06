#!/usr/bin/env python

from setuptools import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
    name="PyZephyr",
    version="0.2.0",
    description="PyZephyr - Python bindings for the Zephyr messaging library",
    author="Evan Broder",
    author_email="broder@mit.edu",
    #url="http://ebroder.net/code/PyZephyr",
    license="MIT",
    requires=['cffi'],
    py_modules=['zephyr'],
    cmdclass= {"build_ext": build_ext},
)
